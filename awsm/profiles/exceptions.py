class ProfileError(Exception):
    pass


class ProfileNotFoundError(Exception):
    def __init__(self, profile):
        message = 'Profile not found: {}'.format(profile)
        super(ProfileNotFoundError, self).__init__(message)


class InvalidProfileError(Exception):
    def __init__(self, profile, errors):
        message = 'Invalid profile: {}\n{}'.format(profile, errors)
        super(InvalidProfileError, self).__init__(message)
