"""CBOR utilities module.

This module provides a unified interface for CBOR operations, isolating the
underlying CBOR library implementation. This allows for easier migration to
different CBOR libraries in the future.

Currently uses cbor2 as the underlying implementation.
"""

from typing import Any, Union

import cbor2

# Type aliases for CBOR special values
CBORTag = cbor2.CBORTag
CBORSimpleValue = cbor2.CBORSimpleValue
CBORDecodeError = cbor2.CBORDecodeError


def encode(obj: Any, canonical: bool = False) -> bytes:
    """Encode an object to CBOR bytes.

    Args:
        obj: The object to encode
        canonical: Whether to use canonical encoding (deterministic)

    Returns:
        CBOR-encoded bytes
    """
    return cbor2.dumps(obj, canonical=canonical)


def decode(data: bytes) -> Any:
    """Decode CBOR bytes to an object.

    Args:
        data: CBOR-encoded bytes

    Returns:
        The decoded object

    Raises:
        CBORDecodeError: If the data is not valid CBOR
    """
    return cbor2.loads(data)


def create_tag(tag: int, value: Any) -> CBORTag:
    """Create a CBOR tag.

    Args:
        tag: The tag number
        value: The tagged value

    Returns:
        A CBOR tag object
    """
    return CBORTag(tag, value)


def create_simple_value(value: int) -> CBORSimpleValue:
    """Create a CBOR simple value.

    Args:
        value: The simple value number (0-255)

    Returns:
        A CBOR simple value object
    """
    return CBORSimpleValue(value)


def is_tag(obj: Any, tag_number: Union[int, None] = None) -> bool:
    """Check if an object is a CBOR tag.

    Args:
        obj: The object to check
        tag_number: Optional specific tag number to check for

    Returns:
        True if the object is a CBOR tag (and matches tag_number if specified)
    """
    if not isinstance(obj, CBORTag):
        return False
    if tag_number is not None:
        return obj.tag == tag_number
    return True


def is_simple_value(obj: Any, value: Union[int, None] = None) -> bool:
    """Check if an object is a CBOR simple value.

    Args:
        obj: The object to check
        value: Optional specific simple value to check for

    Returns:
        True if the object is a CBOR simple value (and matches value if specified)
    """
    if not isinstance(obj, CBORSimpleValue):
        return False
    if value is not None:
        return obj.value == value
    return True


def get_tag_number(obj: CBORTag) -> int:
    """Get the tag number from a CBOR tag.

    Args:
        obj: A CBOR tag object

    Returns:
        The tag number
    """
    return obj.tag


def get_tag_value(obj: CBORTag) -> Any:
    """Get the tagged value from a CBOR tag.

    Args:
        obj: A CBOR tag object

    Returns:
        The tagged value
    """
    return obj.value


def get_simple_value(obj: CBORSimpleValue) -> int:
    """Get the value from a CBOR simple value.

    Args:
        obj: A CBOR simple value object

    Returns:
        The simple value
    """
    return obj.value


# Constants for commonly used tags and simple values
COSE_SIGN1_TAG = 18
REDACTED_CLAIM_ELEMENT_TAG = 60
REDACTED_CLAIM_KEYS_SIMPLE = 59
