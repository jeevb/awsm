import os

from .exceptions import KeyNotFoundError
from .validators import KEY_SCHEMA
from awsm.storage.file_storage import USER_KEYS_CFG
from awsm.utils import load_from_yaml
from voluptuous.humanize import validate_with_humanized_errors


class KeyManager(object):
    def __init__(self):
        super(KeyManager, self).__init__()
        self._keys = None
        self._load_keys()

    def _load_keys(self):
        self._keys = {
            name: validate_with_humanized_errors(config, KEY_SCHEMA)
            for name, config in load_from_yaml(USER_KEYS_CFG).items()
        }

    def get(self, name):
        key = self._keys.get(name)
        if key is None:
            raise KeyNotFoundError(name)
        return key['name'], key['path']

    def find_path(self, name):
        path = None
        try:
            _, path = self.get(name)
        except KeyNotFoundError:
            for key_dict in self._keys.values():
                if name == key_dict['name']:
                    path = key_dict['path']
                    break
        finally:
            if path is None:
                raise KeyNotFoundError(name)

            path = os.path.abspath(os.path.expanduser(path))
            if not os.path.exists(path):
                raise KeyNotFoundError(
                    name, 'Key file \'{}\' does not exist.'.format(path))

            return path
