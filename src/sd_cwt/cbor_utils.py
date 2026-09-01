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


class StrictDecodeError(ValueError):
    """Raised when CBOR is well-formed but not legal in an SD-CWT."""


def _scan_item(data: bytes, offset: int) -> int:
    """Scan one CBOR data item, enforcing the SD-CWT encoding restrictions.

    cbor2 accepts indefinite length encodings and silently keeps the last of a
    set of duplicate map keys. Section 6.4 forbids the first and Section 6.5
    forbids the second, and "last one wins" is exactly the behaviour an attacker
    would use to make two parties read the same bytes differently. So the byte
    stream is walked once before it is handed to cbor2.

    Args:
        data: The CBOR byte stream
        offset: Offset of the item to scan

    Returns:
        The offset just past the scanned item

    Raises:
        StrictDecodeError: On indefinite length encoding or a duplicate map key
        ValueError: On a truncated or malformed stream
    """
    if offset >= len(data):
        raise ValueError("truncated CBOR: expected a data item")

    initial = data[offset]
    major, additional = initial >> 5, initial & 0x1F
    offset += 1

    if additional == 31:
        # Break stops an indefinite length item; reaching one here means the
        # item that opened it was indefinite, which is already rejected below.
        if major in (2, 3, 4, 5):
            raise StrictDecodeError(
                "indefinite length CBOR is not allowed in an SD-CWT (per spec Section 6.4)"
            )
        raise ValueError(f"unexpected break or reserved additional info in major type {major}")

    if additional in (28, 29, 30):
        raise ValueError(f"reserved additional info {additional} in major type {major}")

    if additional < 24:
        value = additional
    else:
        width = 1 << (additional - 24)  # 24->1, 25->2, 26->4, 27->8
        if offset + width > len(data):
            raise ValueError("truncated CBOR: argument runs past the end")
        value = int.from_bytes(data[offset : offset + width], "big")
        offset += width

    if major in (0, 1, 7):  # uint, negint, simple/float
        return offset

    if major in (2, 3):  # bstr, tstr
        if offset + value > len(data):
            raise ValueError("truncated CBOR: string runs past the end")
        return offset + value

    if major == 4:  # array
        for _ in range(value):
            offset = _scan_item(data, offset)
        return offset

    if major == 5:  # map
        seen: set[bytes] = set()
        for _ in range(value):
            key_start = offset
            offset = _scan_item(data, offset)
            key_bytes = data[key_start:offset]
            if key_bytes in seen:
                raise StrictDecodeError(
                    "a CBOR map MUST NOT contain two map keys with the same Preferred "
                    "Encoding (per spec Section 6.5)"
                )
            seen.add(key_bytes)
            offset = _scan_item(data, offset)
        return offset

    # major == 6, tag
    return _scan_item(data, offset)


def assert_strict_cbor(data: bytes) -> None:
    """Reject CBOR that is well-formed but illegal in an SD-CWT.

    Args:
        data: The CBOR byte stream

    Raises:
        StrictDecodeError: On indefinite length encoding or a duplicate map key
    """
    end = _scan_item(data, 0)
    if end != len(data):
        raise ValueError(f"trailing data after the top level CBOR item ({len(data) - end} bytes)")


def decode(data: bytes) -> Any:
    """Decode CBOR bytes to an object.

    Indefinite length encodings and duplicate map keys are rejected before
    decoding; see assert_strict_cbor.

    Args:
        data: CBOR-encoded bytes

    Returns:
        The decoded object

    Raises:
        StrictDecodeError: If the data is well-formed CBOR but illegal here
        CBORDecodeError: If the data is not valid CBOR
    """
    assert_strict_cbor(data)
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
    if not isinstance(obj, CBORSimpleValue):  # type: ignore[misc]
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
