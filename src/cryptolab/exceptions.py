"""CryptoLab exception hierarchy."""


class CryptoLabError(Exception):
    """Base class for expected CryptoLab errors."""

    exit_code = 3


class InputValidationError(CryptoLabError):
    """Raised when structured user input violates a documented format or convention."""


class InputError(CryptoLabError):
    """Raised when a requested input file cannot be read."""

    exit_code = 6


class AuthenticationError(CryptoLabError):
    """Raised when authenticated decryption rejects a tag or associated data."""

    exit_code = 4


class VerificationError(CryptoLabError):
    """Raised when a digest or message-authentication verification fails."""

    exit_code = 4


class DecryptionError(CryptoLabError):
    """Raised when a padded or encoded decryption operation fails."""

    exit_code = 4


class MathematicalDomainError(CryptoLabError):
    """Raised when an operation is undefined for the supplied mathematical input."""


class ResourceLimitError(CryptoLabError):
    """Raised when an educational or resource limit is exceeded."""

    exit_code = 5


class OutputError(CryptoLabError):
    """Raised when a requested output operation cannot be completed."""

    exit_code = 6
