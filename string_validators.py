import re
import uuid
from typing import Optional

# A simple regex for email validation based on common patterns.
# Note: This is not RFC 5322 compliant but covers most common cases.
EMAIL_REGEX = re.compile(
    r"(^[-!#$%&'*+/=?^_`{}|~0-9a-zA-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9a-zA-Z]+)*"
    r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-011\013\014\016-\177])*")'
    r'@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\.?$'
)


def is_email(value: Optional[str]) -> bool:
    """
    Validates if the given string is a valid email address.

    Args:
        value: The string to validate.

    Returns:
        True if the string is a valid email, False otherwise.
    """
    if not isinstance(value, str):
        return False
    return EMAIL_REGEX.match(value) is not None


def is_uuid(value: Optional[str]) -> bool:
    """
    Validates if the given string is a valid UUID (version 1, 3, 4, or 5).

    Args:
        value: The string to validate.

    Returns:
        True if the string is a valid UUID, False otherwise.
    """
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
        return True
    except (ValueError, TypeError):
        return False


def is_alphanumeric(value: Optional[str]) -> bool:
    """
    Validates if the given string contains only alphanumeric characters (a-z, A-Z, 0-9).

    Args:
        value: The string to validate.

    Returns:
        True if the string is alphanumeric, False otherwise.
    """
    if not isinstance(value, str):
        return False
    return value.isalnum()
