from awsm.validators import TAGS_SCHEMA
from awsm.hooks.validators import HOOK_SCHEMA
from voluptuous import All, Coerce, Length, Required, Schema

ROOT_VOLUME_SCHEMA = Schema({
    Required('size'): int,
    Required('type', default='gp2'): str,
    Required('delete_on_termination', default=False): bool
})

VOLUME_SCHEMA = Schema({
    Required('device'): All(str, Coerce(str.lower), Length(min=1, max=1)),
    Required('size'): int,
    Required('type', default='gp2'): str,
    Required('delete_on_termination', default=False): bool
})

PROFILE_SCHEMA = Schema({
    'using': str,
    Required('ami'): str,
    Required('instance_type'): str,
    Required('root_volume'): ROOT_VOLUME_SCHEMA,
    'volumes': [VOLUME_SCHEMA],
    Required('security_groups'): [str],
    'role': str,
    Required('key'): str,
    'tags': TAGS_SCHEMA,
    'on_provision': HOOK_SCHEMA
})
