import re

# Amount of time to spend retrying Boto3 operations in case of failure
BOTO3_WAIT_TIMEOUT = 60

# Usernames to attempt to login into EC2 instances with
AWS_SHELL_USERS = ('ec2-user', 'ubuntu',)

# Pattern to extract block device parameters
EC2_DEVICE_NAME_REGEX = re.compile(
    r'(?P<prefix>/dev/(s|xv)d)(?P<partition>[a-z])(?P<volume>[0-9]+)?')

# Special attribute tags for EC2 resources
PROJECT_TAG_KEY = '__AWSM_PROJECT_ID__'
UUID_TAG_KEY = '__AWSM_UUID__'
RESOURCE_TYPE_KEY = '__AWSM_RESOURCE_TYPE__'
RESERVED_TAG_NAMES = ('Name', PROJECT_TAG_KEY, UUID_TAG_KEY,)
