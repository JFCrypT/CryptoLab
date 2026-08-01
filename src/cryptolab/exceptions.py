"""CryptoLab exception hierarchy."""


class CryptoLabError(Exception):
    """Base class for expected CryptoLab errors."""

    exit_code = 3


class MathematicalDomainError(CryptoLabError):
    """Raised when an operation is undefined for the supplied mathematical input."""


class ResourceLimitError(CryptoLabError):
    """Raised when an educational or resource limit is exceeded."""

    exit_code = 5


class OutputError(CryptoLabError):
    """Raised when a requested output operation cannot be completed."""

    exit_code = 6
