import re

from .exceptions import InvalidTagError
from inflection import camelize
from voluptuous import (
    Coerce,
    Schema,
    Required,
    All,
    Any,
    Length,
    Boolean,
    REMOVE_EXTRA,
    MultipleInvalid
)
from voluptuous.error import Error
from voluptuous.humanize import validate_with_humanized_errors

def tag(val):
    match = re.match(r'(?P<key>\w+)(=(?P<value>.+))?', val)
    if match is None:
        raise ValueError

    tag_key, tag_value = match.group('key', 'value')
    if tag_value is None:
        tag_value = True

    try:
        data = validate_with_humanized_errors(
            {tag_key: tag_value},
            TAGS_SCHEMA
        )
    except Error as e:
        raise InvalidTagError(tag_key, e)
    else:
        return data

def aws_fmt_tag(val):
    try:
        val = AWS_TAGS_SCHEMA(val)
    except MultipleInvalid:
        raise ValueError
    return {val['Key']: val['Value']}

def volume_type(value):
    if not value in ('standard', 'io1', 'gp2', 'sc1', 'st1',):
        raise ValueError
    return value

def yaml_dict(val):
    if val is None:
        return {}
    elif isinstance(val, dict):
        return val
    raise ValueError

IDENTIFIER_SCHEMA = Schema({
    Required('uuid'): str,
    Required('hostname'): str,
    Required('user'): str,
    Required('working_directory'): str,
    Required('availability_zone'): str
}, extra=REMOVE_EXTRA)

TAGS_SCHEMA = Schema({
    All(str, Coerce(camelize)): Any(str, int, bool)
})

AWS_TAGS_SCHEMA = Schema({
    Required('Key'): str,
    Required('Value'): str,
}, extra=REMOVE_EXTRA)

CREATE_VOLUME_SCHEMA = Schema({
    Required('Size'): int,
    'SnapshotId': str,
    Required('AvailabilityZone'): str,
    Required('VolumeType'): All(str, volume_type),
    Required('TagSpecifications'): [{
        Required('ResourceType'): 'volume',
        Required('Tags'): [{
            Required('Key'): str,
            Required('Value'): str
        }]
    }]
})
