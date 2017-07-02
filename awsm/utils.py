import os
import yaml

def load_from_yaml(filename, default=dict()):
    if os.path.exists(filename):
        with open(filename, 'r') as handle:
            data = yaml.load(handle)
            if data is not None:
                return data
    return default

def list_files(directory):
    for root, _, files in os.walk(directory):
        for filename in files:
            # Join the two strings in order to form the full filepath.
            filepath = os.path.join(root, filename)
            yield filepath
