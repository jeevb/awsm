class KeyNotFoundError(Exception):
    def __init__(self, key, reason=None):
        message = 'Key not found: {}'.format(key)
        if reason:
            message = '{}\n{}'.format(message, reason)
        super(KeyNotFoundError, self).__init__(message)
