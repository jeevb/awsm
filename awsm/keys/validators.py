from voluptuous import Required, Schema

KEY_SCHEMA = Schema({
    Required('name'): str,
    Required('path'): str
})
