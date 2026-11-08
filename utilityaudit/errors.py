"""Safe, actionable application errors shared by adapters."""


class ApplicationError(Exception):
    pass


class AccessDenied(ApplicationError):
    pass


class AuthenticationError(ApplicationError):
    pass


class NotFound(ApplicationError):
    pass


class Conflict(ApplicationError):
    pass


class ConfigurationError(ApplicationError):
    pass


class DataIntegrityError(ApplicationError):
    pass
