#!/usr/bin/env python3

from setuptools import setup

setup(
    name='awsm',
    version='0.0.1',
    author='Sanjeev Balakrishnan',
    author_email='me@jeev.io',
    packages=['awsm',],
    scripts=['bin/awsm',],
    description='A wrapper for using AWS EC2 resources.',
    install_requires=[
        'ansible>=2.3.0.0',
        'argh>=0.26.2',
        'bgtunnel>=0.4.1',
        'boto3>=1.4.4',
        'botocore>=1.5.43',
        'docker==2.1.0',
        'Fabric3>=1.13.1.post1',
        'gevent>=1.2.1',
        'inflection>=0.3.1',
        'networkx>=1.11',
        'peewee>=2.10.1',
        'PTable>=0.9.2',
        'PyYAML>=3.12',
        'voluptuous>=0.10.5',
    ],
    zip_safe=True,
    include_package_data = True
)
