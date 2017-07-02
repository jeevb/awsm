import os
import sys

from contextlib import contextmanager
from botocore.exceptions import ClientError

@contextmanager
def warn_on_error():
    try:
        yield
    except ClientError as e:
        message = e.response.get('Error', {}).get('Message')
        if message:
            print(message, file=sys.stderr)
    except Exception as e:
        print(e, file=sys.stderr)

@contextmanager
def shell_env(**kwargs):
    old_environ = dict(os.environ)
    os.environ.update(kwargs)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(old_environ)
