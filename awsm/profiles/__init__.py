import networkx as nx

from .exceptions import (
    ProfileError,
    ProfileNotFoundError,
    InvalidProfileError
)
from .validators import PROFILE_SCHEMA
from awsm.storage.file_storage import USER_PROFILES_DIR, PROJECT_PROFILES_CFG
from awsm.utils import load_from_yaml, list_files
from networkx import NetworkXError
from voluptuous.error import Error
from voluptuous.humanize import validate_with_humanized_errors


class ProfileManager(object):
    def __init__(self):
        super(ProfileManager, self).__init__()
        self._profiles = {}
        self._dag = nx.DiGraph()
        self._load_profiles()

    @property
    def configs(self):
        # Splinter configs in user Awsm root directory
        yield from list_files(USER_PROFILES_DIR)

        # Override in current working directory
        yield PROJECT_PROFILES_CFG

    def _load_profiles(self):
        for file_path in self.configs:
            self._profiles.update(load_from_yaml(file_path))

        for name, profile in self._profiles.items():
            self._dag.add_node(name)
            using = profile.get('using')
            if using is not None:
                self._dag.add_path([using, name])

        # Validate workflow
        if not nx.is_directed_acyclic_graph(self._dag):
            raise ProfileError('Profiles contain cyclic dependencies.')

        # Validate all nodes in profiles
        for node in self._dag.nodes_iter():
            self.get(node)

    def _validate_profile(self, name):
        profile = {}
        nodes = nx.ancestors(self._dag, name)
        nodes.add(name)
        for node in nx.topological_sort(self._dag):
            if node in nodes:
                profile.update(self._profiles.get(node, {}))

        # Validate and return
        return validate_with_humanized_errors(profile, PROFILE_SCHEMA)

    def get(self, name):
        try:
            profile = self._validate_profile(name)
        except NetworkXError:
            raise ProfileNotFoundError(name)
        except Error as e:
            raise InvalidProfileError(name, e)
        else:
            return profile

    def __call__(self, **kwargs):
        using = kwargs.pop('using')
        profile = self.get(using) if using is not None else {}
        profile.update(**kwargs)
        return validate_with_humanized_errors(profile, PROFILE_SCHEMA)
