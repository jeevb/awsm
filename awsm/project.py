# Monkey patch ansible host key checking
from ansible import constants
setattr(constants, 'HOST_KEY_CHECKING', False)

import os
import base64
import boto3
import docker
import getpass
import itertools
import json
import random
import socket
import sys
import time
import uuid
import yaml

from .constants import *
from .context_managers import shell_env
from .exceptions import (
    ProjectError,
    InvalidAvailabilityZone,
    InvalidResource,
    CannotDetachVolume,
    CannotAttachVolume,
    CannotFindRunningInstance,
    CannotLoginToInstance
)
from .hooks import HooksManager, HookExecutor
from .keys import KeyManager
from .prettytable import InstanceTable, VolumeTable
from .profiles import ProfileManager
from .storage.database import PROJECT_DB as db
from .storage.file_storage import (
    PROJECT_CFG_DIR,
    PROJECT_IDENTITY,
    PROJECT_TAGS
)
from .transport import ssh_tunnel
from .utils import load_from_yaml
from .validators import (
    aws_fmt_tag,
    IDENTIFIER_SCHEMA,
    TAGS_SCHEMA,
    CREATE_VOLUME_SCHEMA
)
from botocore.exceptions import ClientError
from inflection import underscore
from fabric.api import settings, hide, local, run
from functools import wraps
from string import ascii_lowercase as letters
from voluptuous import Error
from voluptuous.humanize import validate_with_humanized_errors


class Project(object):
    ##
    ## Decorators
    ##

    def requires_project_cfg_dir(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            os.makedirs(PROJECT_CFG_DIR, exist_ok=True)
            return func(*args, **kwargs)
        return wrapper

    def retry_with_timeout(timeout, interval=1):
        def decorator(func):
            def wrapper(*args, **kwargs):
                start = time.time()
                while time.time() < start + timeout:
                    result = func(*args, **kwargs)
                    if result:
                        return result
                    time.sleep(interval)
            return wrapper
        return decorator

    def __init__(self):
        super(Project, self).__init__()

        # TODO(jeev): Validate proper initialization of boto session
        # Required variables for AWS
        self._session = boto3.session.Session()
        self._client = self._session.client('ec2')
        self._resource = self._session.resource('ec2')

        # Initialize the project DB
        self._load_db()

        # Identifier
        self._identifier = None
        self._load_existing_identity()

        # Tags
        self._extra_tags = None
        self._load_tags()

        # Initialize profiles manager
        self._profiles = ProfileManager()

        # Initialize key manager
        self._keys = KeyManager()

        # Initialize hooks manager
        self._hooks = HooksManager()

    ##
    ## Project Attributes
    ##

    @property
    def profile_manager(self):
        return self._profiles

    @property
    def identifier(self):
        if not self._identifier:
            self.create_identity()
        return self._identifier

    @identifier.setter
    def identifier(self, value):
        if self._identifier is not None:
            raise ProjectError('An identity already exists for this project.')
        self._identifier = validate_with_humanized_errors(
            value,
            IDENTIFIER_SCHEMA
        )

    @property
    def available_zones(self):
        response = self._client.describe_availability_zones()
        zones = response.get('AvailabilityZones', None) or []
        return [i['ZoneName'] for i in zones if i['State'] == 'available']

    @property
    def identifier_hash(self):
        dump = json.dumps(self.identifier, sort_keys=True).encode('utf-8')
        return base64.b64encode(dump).decode('utf-8')

    @property
    def availability_zone(self):
        return self.identifier.get('availability_zone')

    @property
    def uuid(self):
        return self.identifier.get('uuid')

    @property
    def name(self):
        return underscore(
            'awsm_{hostname}_{user}_{project}'.format(
                hostname=self.identifier['hostname'],
                user=self.identifier['user'],
                project=os.path.basename(self.identifier['working_directory'])
            )
        )

    @property
    def filters(self):
        return {UUID_TAG_KEY: self.uuid}

    ##
    ## Database
    ##

    @requires_project_cfg_dir
    def _load_db(self):
        db.connect()

    ##
    ## Identity
    ##

    @requires_project_cfg_dir
    def _load_existing_identity(self):
        if os.path.exists(PROJECT_IDENTITY):
            with open(PROJECT_IDENTITY) as handle:
                self.load_identity(handle.read())

    def load_identity(self, identifier):
        self.identifier = json.loads(
            base64.b64decode(identifier.encode('utf-8')).decode('utf-8'))

        with open(PROJECT_IDENTITY, 'w') as handle:
            print(self.identifier_hash, file=handle)

    def create_identity(self, availability_zone=None):
        if (
                availability_zone is not None and
                availability_zone not in set(self.available_zones)
        ):
            raise InvalidAvailabilityZone(availability_zone)

        self.identifier = {
            'availability_zone': (
                availability_zone or
                random.choice(self.available_zones)
            ),
            'hostname': socket.gethostname(),
            'user': getpass.getuser(),
            'uuid': uuid.uuid4().hex,
            'working_directory': os.getcwd()
        }

        with open(PROJECT_IDENTITY, 'w') as handle:
            print(self.identifier_hash, file=handle)

    def show_identity(self):
        yaml.dump(self.identifier, sys.stdout, default_flow_style=False)
        border = '-' * 10
        print(border, self.identifier_hash, border, sep='\n')

    ##
    ## Tags
    ##

    @property
    def tags(self):
        tags = {PROJECT_TAG_KEY: self.name}
        tags.update(self.filters)
        tags.update(self._extra_tags)
        return tags

    # TODO (jeev): Move project tags to DB
    @requires_project_cfg_dir
    def _load_tags(self):
        self._extra_tags = load_from_yaml(PROJECT_TAGS)

    def set_project_tags(self, tags, refresh=False, remove=False):
        if refresh:
            # Clear existing tags
            self._extra_tags.clear()
        elif not tags:
            if self._extra_tags:
                yaml.dump(self._extra_tags,
                          sys.stdout,
                          default_flow_style=False)
            return

        if isinstance(tags, (list, tuple)):
            tmp = {}
            for tag in tags:
                tmp.update(tag)
            tags = tmp

        if tags:
            # Validate tags
            tags = validate_with_humanized_errors(tags, TAGS_SCHEMA)

            for key, value in tags.items():
                if not remove:
                    if key in RESERVED_TAG_NAMES:
                        print('\'{}\''.format(key),
                              'is a reserved tag name.',
                              file=sys.stderr)
                        continue
                    print('Setting tag: {}={}'.format(key, value))
                    self._extra_tags[key] = value
                elif key in self._extra_tags:
                    print('Deleting tag: {}'.format(key))
                    del self._extra_tags[key]

        # Update project tags
        with open(PROJECT_TAGS, 'w') as handle:
            yaml.dump(self._extra_tags, handle, default_flow_style=False)

    def _fmt_tags(self, tags=None):
        tags = tags or self.tags
        _tags = []
        for k, v in tags.items():
            _tags.append({'Key': str(k), 'Value': str(v)})
        return _tags

    ##
    ## EC2 Helpers
    ##

    def _get_device_info_for_image(self, image):
        response = self._client.describe_images(ImageIds=[image])['Images'][0]
        root_device_name = response['RootDeviceName']
        return (
            root_device_name,
            EC2_DEVICE_NAME_REGEX.match(root_device_name).group('prefix')
        )

    def _get_streaming_response(self, api_method, key, **kwargs):
        response = api_method(**kwargs)
        yield from response.get(key, [])

        next_token = response.get('nextToken')
        while next_token is not None:
            response = api_method(nextToken=next_token, **kwargs)
            yield from response.get(key, [])
            next_token = response.get('nextToken')

    @retry_with_timeout(BOTO3_WAIT_TIMEOUT)
    def _wait_for_state(self, resource, **states):
        # Reload the resource
        resource.load()

        # If at least one condition is not met, resource is not ready.
        ready = True
        for attr, allowed_values in states.items():
            value = getattr(resource, attr)
            if value not in allowed_values:
                ready = False
        return ready

    def _infer_resource_type(self, resource_id):
        # Sanity check to make sure resource ID is a string
        if isinstance(resource_id, str):
            # Infer the type of resource
            if resource_id.startswith('i-'):
                return 'instance'
            elif resource_id.startswith('vol-'):
                return 'volume'

    def get_resource_attrs(self, resource_id, restrict_to_project=True):
        # Make sure resource ID is valid
        resource_type = self._infer_resource_type(resource_id)
        if not resource_type:
            return

        # Update tags with resource type
        tags = {RESOURCE_TYPE_KEY: resource_type}

        # Get additional tags for resource
        response = self._client.describe_tags(
            Filters=[{
                    'Name': 'resource-id',
                    'Values': [resource_id]
            }]
        ).get('Tags', [])

        if response:
            # Collapse tags
            for tag in response:
                tags.update(aws_fmt_tag(tag))

        # Ensure that resource belongs to this project
        if not restrict_to_project or tags.get(UUID_TAG_KEY) == self.uuid:
            return tags

    def get_valid_resource_type(self, resource_id):
        tags = self.get_resource_attrs(resource_id, restrict_to_project=True)
        if tags is not None:
            return tags.get(RESOURCE_TYPE_KEY)

    def get_resource(self, resource_id, expected_resource_type=None):
        resource_type = self.get_valid_resource_type(resource_id)
        valid = (
            resource_type is not None and
            (expected_resource_type is None or
             resource_type == expected_resource_type)
        )

        if not valid:
            raise InvalidResource(resource_id, expected_resource_type)

        handler = getattr(self, '_get_{}'.format(resource_type), None)
        if handler:
            return handler(resource_id)

    def _get_instance(self, instance_id):
        instance = self._resource.Instance(instance_id)
        instance.load()
        return instance

    def _get_volume(self, volume_id):
        volume = self._resource.Volume(volume_id)
        volume.load()
        return volume

    ##
    ## EC2 Resource Tags
    ##

    def set_resource_tags(self,
                          resources,
                          tags,
                          refresh=True,
                          remove=False):
        if not tags:
            for resource in resources:
                tags = self.get_resource_attrs(resource)
                if tags is not None:
                    print(resource)
                    print('-' * len(resource))
                    yaml.dump(tags, sys.stdout, default_flow_style=False)
            return

        if isinstance(tags, (list, tuple)):
            tmp = {}
            for tag in tags:
                tmp.update(tag)
            tags = tmp

        # Validate tags
        tags = validate_with_humanized_errors(tags, TAGS_SCHEMA)

        # Remove tags instead of adding
        if remove:
            tags = [{'Key': k} for k in tags]
            self._client.delete_tags(Resources=resources, Tags=tags)
            return

        if refresh:
            # Clear existing tags
            self._client.delete_tags(Resources=resources)

            # Add tags for this project
            new_tags = self.tags
            new_tags.update(tags)
            tags = new_tags

        self._set_resource_tags(*resources, **tags)

    def _set_resource_tags(self, *resources, **tags):
        self._resource.create_tags(Resources=resources,
                                   Tags=self._fmt_tags(tags))

    ##
    ## Ansible Integration
    ##

    def run_hooks_on_instance(self,
                              *instance_id,
                              hook=None,
                              config=None,
                              task_vars=None):
        # Nothing specified to be run
        if hook is None and config is None:
            return

        instance = None
        attrs = None
        hosts = []

        # Validate and collect attributes for every instance
        for iid in instance_id:
            instance, attrs = self.find_usable_instance(iid)
            hosts.append(attrs['host_string'])

        # Prepare vars for ansible Play
        play_vars = {'gather_facts': False}

        executor = HookExecutor(attrs['username'],
                                attrs['key_filename'],
                                *hosts,
                                task_vars=task_vars or {},
                                play_vars=play_vars)
        executor.manager = self._hooks
        executor(hook=hook, config=config)

    ##
    ## EC2 Instances
    ##

    def provision(self, name, count=1):
        print('Provisioning profile:', name)

        profile = self._profiles.get(name)

        # Get device naming convention for image
        root_device, device_prefix = self._get_device_info_for_image(
            profile['ami'])

        # Construct list of volumes to launch profile with
        volumes = profile.get('volumes') or []
        for volume in volumes:
            volume['device'] = device_prefix + volume['device']

        # Update and add definition for root volume
        root_volume = profile['root_volume']
        root_volume['device'] = root_device
        volumes.append(root_volume)

        # Retrieve key to use for resource
        key_profile = profile['key']
        key_name, _ = self._keys.get(key_profile)

        request = dict(
            ImageId=profile['ami'],
            MinCount=count,
            MaxCount=count,
            KeyName=key_name,
            SecurityGroups=profile['security_groups'],
            InstanceType=profile['instance_type'],
            Placement={'AvailabilityZone': self.availability_zone},
            BlockDeviceMappings=[
                {
                    'DeviceName': volume['device'],
                    'Ebs': {
                        'VolumeSize': volume['size'],
                        'VolumeType': volume['type'],
                        'DeleteOnTermination': volume['delete_on_termination']
                    }
                }
                for volume in volumes
            ]
        )

        # If a role is specified, use it
        role = profile.get('role')
        if role is not None:
            request.update({'IamInstanceProfile': {'Name': role}})

        # Create the instances
        response = self._resource.create_instances(**request)

        # Make a list of all elements provisioned for this profile
        # Properly tag all elements
        tags = self.tags
        profile_tags = profile.get('tags', {})
        profile_name = profile_tags.pop('Name', None) or self.name
        profile_uid = uuid.uuid4().hex[:6]
        tags.update(profile_tags)

        # Profile-specific 'on_provision' hook override
        on_provision = profile.get('on_provision')

        instance_ids = []
        for idx, instance in enumerate(response):
            elements = []

            # Block until the instance is SSHable
            # TODO(jeev): Use coroutines for this
            instance.wait_until_running()
            self._wait_until_usable(instance)

            elements.append(instance.id)

            for volume in instance.volumes.all():
                elements.append(volume.id)

            self._set_resource_tags(
                Name='{}_{}_{}_run_{}'.format(
                    profile_name,
                    name,
                    profile_uid,
                    idx
                ),
                *elements,
                **tags
            )

            instance_ids.append(instance.id)

        # Run hooks
        self.run_hooks_on_instance(
            *instance_ids,
            hook='on_provision',
            config=on_provision
        )

        return instance_ids

    def ls(self, all=False, quiet=False, verbose=True):
        filters = [
            {'Name': 'tag:{}'.format(k), 'Values': [v]}
            for k, v in self.filters.items()
        ]

        if not all:
            filters.append({
                'Name': 'instance-state-name',
                'Values': ['pending', 'running',]
            })

        stream = self._get_streaming_response(
            self._client.describe_instances,
            key='Reservations',
            Filters=filters
        )

        table = InstanceTable(skip_tags=set(self.tags.keys()))
        table.load_stream(
            itertools.chain.from_iterable(i['Instances'] for i in stream))

        if verbose:
            output = (
                table.get_string(header=False, fields=['ID'])
                if quiet else
                table.get_string()
            )
            if output:
                print(output)

        return table

    def enroll(self, resource_id):
        resource_type = self._infer_resource_type(resource_id)
        if not resource_type:
            raise InvalidResource(resource_id)

        elements = [resource_id]
        # If resource is an instance, enroll all of its volumes
        if resource_type == 'instance':
            resource = self._get_instance(resource_id)

            # Instance must be in the correct availability zone
            if (
                    resource.placement['AvailabilityZone'] !=
                    self.availability_zone
            ):
                raise InvalidResource(resource_id)

            for volume in resource.volumes.all():
                elements.append(volume.id)

        # If resource is a volume, enroll the instance it is attached to
        elif resource_type == 'volume':
            resource = self._get_volume(resource_id)

            # Volume must be in the correct availability zone
            if resource.availability_zone != self.availability_zone:
                raise InvalidResource(resource_id)

            for attachment in resource.attachments:
                elements.append(attachment['InstanceId'])

        # Set tags for all related elements
        self._set_resource_tags(*elements)

    def start(self, instance_id):
        print('Starting instance:', instance_id)
        instance = self.get_resource(instance_id, 'instance')
        instance.start()

        # Block until the instance is SSHable
        # TODO(jeev): Use coroutines for this
        instance.wait_until_running()
        self._wait_until_usable(instance)

    def rm(self, instance_id, remove_volumes=False):
        print('Removing instance:', instance_id)
        instance = self.get_resource(instance_id, 'instance')

        # Track volumes attached to this instance
        attached_volumes = [v.id for v in instance.volumes.all()]

        # Terminate instance
        instance.terminate()
        instance.wait_until_terminated()

        # Clean up volumes if necessary
        if remove_volumes:
            print('Removing volumes for instance.')
            for v in attached_volumes:
                try:
                    _v = self._get_volume(v)
                    _v.delete()
                except ClientError:
                    pass

    def stop(self, instance_id):
        print('Stopping instance:', instance_id)
        instance = self.get_resource(instance_id, 'instance')
        instance.stop()
        instance.wait_until_stopped()

    ##
    ## EC2 Instance Access
    ##

    @retry_with_timeout(BOTO3_WAIT_TIMEOUT, interval=5)
    def _find_username(self, host_string, key_filename):
        for user in AWS_SHELL_USERS:
            try:
                with settings(
                        hide('running',
                             'warnings',
                             'aborts',
                             'stdout',
                             'stderr'),
                        host_string=host_string,
                        user=user,
                        abort_on_prompts=True,
                        key_filename=key_filename,
                        warn_only=True
                ):
                    run('ls')
                    return user
            except:
                pass

    def _get_instance_ssh_attrs(self, instance):
        if not isinstance(instance, boto3.resources.base.ServiceResource):
            instance = self.get_resource(instance, 'instance')
        else:
            instance.load()

        key_filename = self._keys.find_path(instance.key_name)

        host_string = instance.public_ip_address
        if not host_string:
            raise CannotLoginToInstance(
                instance.id, 'No public IP address available.')

        username = self._find_username(host_string, key_filename)
        if not username:
            raise CannotLoginToInstance(
                instance.id, 'Cannot find a valid shell user.')

        return instance, {
            'key_filename': key_filename,
            'host_string': host_string,
            'username': username
        }

    def _get_single_running_instance(self):
        instance_table = self.ls(verbose=False)
        running = [
            instance
            for instance in instance_table.data
            if instance['State'] == 'running'
        ]

        # Handle the case of no running instances
        if not running:
            raise CannotFindRunningInstance('No running instances found.')
        # Handle ambiguity - too many running instances
        elif len(running) != 1:
            raise CannotFindRunningInstance(
                'Multiple running instances found.')

        # One running instance found
        return running[0]['ID']

    def find_usable_instance(self,
                             instance=None,
                             raise_exception=True,
                             verbose=False):
        if instance is None:
            instance = self._get_single_running_instance()

        try:
            return self._get_instance_ssh_attrs(instance)
        except Exception as e:
            if raise_exception:
                raise
            if verbose:
                print(e, file=sys.stderr)

    @retry_with_timeout(BOTO3_WAIT_TIMEOUT)
    def _wait_until_usable(self, instance):
        return self.find_usable_instance(instance, raise_exception=False)

    def ssh(self, instance_id):
        _, attrs = self.find_usable_instance(instance_id)

        with settings(
                hide('running', 'warnings',),
                warn_only=True
        ):
            local("""
                ssh \
                    -o PreferredAuthentications=publickey \
                    -o StrictHostKeyChecking=no \
                    -i {key_filename} \
                    {username}@{host_string}
            """.format(**attrs))

    def machine(self, instance_id):
        instance, attrs = self.find_usable_instance(instance_id)

        tunnel = ssh_tunnel.start(
            attrs['host_string'],
            attrs['username'],
            attrs['key_filename'],
            self._hooks.get_var('remote_docker_port', 2375)
        )

        with shell_env(
                DOCKER_HOST='tcp://{}'.format(tunnel.bind_string),
                DOCKER_MACHINE_NAME=instance.id
        ):
            with settings(
                    hide('running', 'warnings',),
                    warn_only=True
            ):
                local("""
                    /bin/bash \
                        --rcfile <(echo \'PS1="[{}] \\w$ "\')
                """.format(instance.id), shell='/bin/bash')

    ##
    ## EC2 Volumes
    ##

    def volumes(self, all=False, quiet=False, verbose=True):
        filters = [
            {'Name': 'tag:{}'.format(k), 'Values': [v]}
            for k, v in self.filters.items()
        ]

        if not all:
            filters.append({
                'Name': 'status',
                'Values': ['creating', 'available',]
            })

        stream = self._get_streaming_response(
            self._client.describe_volumes,
            key='Volumes',
            Filters=filters
        )

        table = VolumeTable(skip_tags=set(self.tags.keys()))
        table.load_stream(stream)

        if verbose:
            output = (
                table.get_string(header=False, fields=['ID'])
                if quiet else
                table.get_string()
            )
            if output:
                print(output)

        return table

    def create_volume(self,
                      instance_id,
                      size,
                      type='gp2',
                      snapshot=None):
        instance = self.get_resource(instance_id, 'instance')

        request = {
            'Size': size,
            'AvailabilityZone': self.availability_zone,
            'VolumeType': type,
            'TagSpecifications': [{
                'ResourceType': 'volume',
                'Tags': instance.tags
            }]
        }

        if snapshot is not None:
            request.update({'SnapshotId': snapshot})

        request = validate_with_humanized_errors(request, CREATE_VOLUME_SCHEMA)
        volume = self._resource.create_volume(**request)

        # Wait for volume to become available
        self._wait_for_state(volume, state=('available',))

        return self.attach_volume(instance_id, volume.id)

    def _attach_volume_helper(self, instance_id, volume_id, device_name):
        volume = self.get_resource(volume_id, 'volume')

        # Find instance this volume is attached to
        if volume.attachments:
            raise CannotAttachVolume(
                volume_id, 'Volume is attached to another instance.')

        print('Attaching volume:', volume_id)
        volume.attach_to_instance(InstanceId=instance_id, Device=device_name)

    def attach_volume(self, instance_id, *volume_ids):
        instance = self.get_resource(instance_id, 'instance')

        # Get device name prefix for instance
        device_prefix = (
            EC2_DEVICE_NAME_REGEX
            .match(instance.root_device_name)
            .group('prefix')
        )

        # Get the maximum mounted device name ID
        curr_char = max(
            EC2_DEVICE_NAME_REGEX
            .match(i.get('DeviceName'))
            .group('partition')
            for i in instance.block_device_mappings
        )
        next_id = max(letters.index('f'), letters.index(curr_char) + 1)

        for volume_id in volume_ids:
            try:
                self._attach_volume_helper(
                    instance_id,
                    volume_id,
                    device_prefix + letters[next_id]
                )
            except CannotAttachVolume as e:
                print(e, file=sys.stderr)
            else:
                # Increment ID for next device
                next_id += 1

        # Run hook on attaching volumes
        self.run_hooks_on_instance(instance_id, hook='on_attach_volume')

    def detach_volume(self, volume_id, force=False):
        volume = self.get_resource(volume_id, 'volume')

        # Find instance this volume is attached to
        if not volume.attachments:
            return

        instance_id = volume.attachments[0]['InstanceId']
        instance = self.get_resource(instance_id, 'instance')

        # Instance should be stopped if volume is to be detached
        if (
                not force
                and instance.state['Name'] not in ('stopped', 'terminated',)
        ):
            raise CannotDetachVolume(
                volume_id, 'The attached instance is still running.')

        print('Detaching volume:', volume_id)
        volume.detach_from_instance({
            'InstanceId': instance_id,
            'Force': force
        })

    def rm_volume(self, volume_id):
        print('Removing volume:', volume_id)
        volume = self.get_resource(volume_id, 'volume')
        volume.delete()
