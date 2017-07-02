from argh import arg, ArghParser, add_commands, dispatch

DEFAULT_NAMESPACE = '__DEFAULT_NAMESPACE__'


class EntryPoint(object):
    def __init__(self, name, **kwargs):
        self._name = name
        self._namespaces = []
        self._default_namespace = self.namespace(DEFAULT_NAMESPACE)
        self._kwargs = kwargs or {}

    def __call__(self, f=None):
        if f:
            return self._default_namespace(f)
        return self._dispatch()

    def _dispatch(self):
        parser = ArghParser(**self._kwargs)
        for ns in self._namespaces:
            name = ns.name if ns.name != DEFAULT_NAMESPACE else None
            add_commands(parser,
                         ns.commands,
                         namespace=name,
                         namespace_kwargs=ns.kwargs)
        dispatch(parser)

    def namespace(self, name, **kwargs):
        ns = _Namespace(name, **kwargs)
        self._namespaces.append(ns)
        return ns


class _Namespace(object):
    def __init__(self, name, **kwargs):
        super(_Namespace, self).__init__()
        self.name = name
        self.commands = []
        self.kwargs = kwargs or {}

    def __call__(self, f):
        self.commands.append(f)
        return f
