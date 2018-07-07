import networkx as nx

from .exceptions import HookError
from .validators import HOOKS_CFG_SCHEMA
from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.inventory import Inventory
from ansible.parsing.dataloader import DataLoader
from ansible.playbook.play import Play
from ansible.vars import VariableManager
from awsm.storage.file_storage import (
    USER_HOOKS_DIR,
    PROJECT_HOOKS_CFG
)
from awsm.utils import load_from_yaml, list_files
from collections import namedtuple
from voluptuous.humanize import validate_with_humanized_errors


class HooksManager(object):
    def __init__(self):
        super(HooksManager, self).__init__()
        self._vars = {}
        self._hooks = {}
        self._dag = nx.DiGraph()
        self._load_hooks()

    @property
    def vars(self):
        return self._vars

    @property
    def configs(self):
        # Splinter configs in user Awsm root directory
        yield from list_files(USER_HOOKS_DIR)

        # Override in current working directory
        yield PROJECT_HOOKS_CFG

    def _load_hooks(self):
        for file_path in self.configs:
            data = validate_with_humanized_errors(
                load_from_yaml(file_path),
                HOOKS_CFG_SCHEMA
            )
            self._vars.update(data.pop('vars', {}))
            self._hooks.update(data)

        for name, hook in self._hooks.items():
            self._dag.add_node(name)
            includes = hook.get('includes')
            if includes is not None:
                for include in includes:
                    if include not in self._hooks:
                        raise HookError(
                            'Unrecognized hook: {}'.format(include))
                    self._dag.add_path([include, name])

        # Validate workflow
        if not nx.is_directed_acyclic_graph(self._dag):
            raise HookError('Hooks contain cyclic dependencies.')

    def get_task_list_from_names(self, *names):
        # Sanity check for hooks that do not exist
        not_found = set(names) - self._hooks.keys()
        if not_found:
            raise HookError('Unrecognized hooks: {}'.format(
                ', '.join(not_found)
            ))

        # Build a set of nodes that we need to extract tasks for
        nodes = set(
            node
            for name in names
            for node in nx.ancestors(self._dag, name)
        )
        nodes.update(names)

        # Yield tasks for the given hooks
        yield from (
            task
            for node in nx.topological_sort(self._dag.subgraph(nodes))
            for task in self._hooks.get(node, {}).get('tasks', [])
        )

    def get_task_list_from_config(self, config):
        # Get dependencies
        yield from self.get_task_list_from_names(*config.get('includes', []))

        # Get "inline" tasks in config
        yield from config.get('tasks', [])

    def get_var(self, name, default=None):
        return self._vars.get(name, default)


Options = namedtuple(
    'Options',
    [
        'connection',
        'module_path',
        'forks',
        'become',
        'become_method',
        'become_user',
        'check',
        'remote_user',
        'private_key_file',
    ]
)


class HookExecutor(object):
    def __init__(self,
                 user,
                 key_filename,
                 *host,
                 task_vars=None,
                 play_vars=None):
        super(HookExecutor, self).__init__()

        self._manager = None

        self._hosts = list(host) or []
        self._play_vars = play_vars or {}
        self._loader = DataLoader()

        self._task_vars = task_vars or {}
        self._var_mgr = VariableManager()

        inventory = Inventory(host_list=self._hosts,
                              loader=self._loader,
                              variable_manager=self._var_mgr)
        options = Options(connection='ssh',
                          module_path=None,
                          forks=100,
                          become=True,
                          become_method='sudo',
                          become_user='root',
                          check=False,
                          remote_user=user,
                          private_key_file=key_filename)
        self._tqm = TaskQueueManager(inventory=inventory,
                                     variable_manager=self._var_mgr,
                                     loader=self._loader,
                                     options=options,
                                     passwords=None)

    @property
    def manager(self):
        return self._manager

    @manager.setter
    def manager(self, value):
        assert isinstance(value, HooksManager), (
            'Invalid hooks manager. Expected: {} '
            'Got: {}'
        ).format(HooksManager.__name__, value.__class__.__name__)
        self._manager = value

    def __call__(self, hook=None, config=None):
        # Nothing specified to be run
        if hook is None and config is None:
            return

        # Make sure that a manager is set for this hook.
        assert self.manager is not None, 'Hook executed without a manager.'

        task_list = list(
            self.manager.get_task_list_from_config(config)
            if config is not None else
            self.manager.get_task_list_from_names(hook)
        )

        # No tasks to run
        if not task_list:
            return

        # Set task variables for play
        task_vars = self.manager.vars.copy()
        task_vars.update(self._task_vars)
        self._var_mgr.extra_vars = task_vars

        data = {'hosts': self._hosts, 'tasks': task_list}
        data.update(self._play_vars)

        # Initialize an ansible play
        play = Play.load(data,
                         variable_manager=self._var_mgr,
                         loader=self._loader)

        # Run the tasks
        try:
            self._tqm.run(play=play)
        finally:
            self._tqm.cleanup()
            self._loader.cleanup_all_tmp_files()
