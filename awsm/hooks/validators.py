from awsm.validators import yaml_dict
from voluptuous import All, Coerce, Schema

HOOK_SCHEMA = Schema(All(Coerce(yaml_dict), {
    'includes': [str],
    'tasks': [dict]
}))

HOOK_VARS_SCHEMA = All(Coerce(yaml_dict), dict)

HOOKS_CFG_SCHEMA = Schema({
    'vars': HOOK_VARS_SCHEMA,
    str: HOOK_SCHEMA
})
