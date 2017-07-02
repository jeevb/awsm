import atexit
import bgtunnel
import socket
import time

from .exceptions import SSHTunnelError


class SSHTunnel(object):
    def __init__(self):
        super(SSHTunnel, self).__init__()
        self._cache = {}

    @staticmethod
    def _check_tunnel(tunnel, timeout=10):
        if not tunnel.isAlive():
            tunnel.start()

        done = False
        valid = False
        start = time.time()

        while not done and time.time() - start < timeout:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)

            try:
                s.connect((tunnel.bind_address, tunnel.bind_port))
            except ConnectionRefusedError:
                time.sleep(.1)
            except socket.error:
                done = True
            else:
                done = True
                valid = True
            finally:
                s.close()

        if not valid:
            raise SSHTunnelError(tunnel.host_address, tunnel.host_port)

    def start(self, host, user, private_key, remote_port):
        # Try retrieving a valid tunnel from the cache
        tunnel = self._cache.get((host, user, private_key, remote_port))

        # Create a new tunnel
        if tunnel is None:
            tunnel = bgtunnel.open(
                host,
                ssh_user=user,
                identity_file=private_key,
                host_port=remote_port,
                expect_hello=False,
                silent=True,
                strict_host_key_checking=False
            )

            # Cache new tunnel
            self._cache[host, user, private_key, remote_port] = tunnel

        # Check tunnel
        self._check_tunnel(tunnel)

        return tunnel

    def stop(self):
        for tunnel in self._cache.values():
            tunnel.close()


ssh_tunnel = SSHTunnel()
atexit.register(ssh_tunnel.stop)
