class SSHTunnelError(Exception):
    def __init__(self, host, port):
        message = 'Cannot establish an SSH tunnel to \'{}:{}\''.format(
            host, port)
        super(SSHTunnelError, self).__init__(message)
