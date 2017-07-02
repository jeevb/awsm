##
## Project
##

class ProjectError(Exception):
    pass


class InvalidAvailabilityZone(Exception):
    def __init__(self, availability_zone):
        message = 'Availability Zone is invalid or unusable: {}'.format(
            availability_zone)
        super(InvalidAvailabilityZone, self).__init__(message)

##
## Tags
##

class InvalidTagError(Exception):
    def __init__(self, tag, errors):
        message = 'Invalid tag: {}\n{}'.format(tag, errors)
        super(InvalidProfileError, self).__init__(message)

##
## EC2 Resources
##

class InvalidResource(Exception):
    def __init__(self, resource_id, resource_type=None):
        message = 'Invalid or unavailable {}: {}'.format(
            resource_type or 'resource', resource_id)
        super(InvalidResource, self).__init__(message)

##
## EC2 Volumes
##

class CannotDetachVolume(Exception):
    def __init__(self, volume, reason):
        message = 'Volume, \'{}\', cannot be detached. {}'.format(
            volume, reason)
        super(CannotDetachVolume, self).__init__(message)


class CannotAttachVolume(Exception):
    def __init__(self, volume, reason):
        message = 'Volume, \'{}\', cannot be attached. {}'.format(
            volume, reason)
        super(CannotDetachVolume, self).__init__(message)

##
## EC2 Instances
##

class CannotFindRunningInstance(Exception):
    pass


class CannotLoginToInstance(Exception):
    def __init__(self, instance, reason):
        message = 'Cannot log in to instance: {}\n{}'.format(
            instance, reason)
        super(CannotLoginToInstance, self).__init__(message)
