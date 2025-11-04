"""EDN (Extended Diagnostic Notation) utilities wrapper.

This module provides a unified interface for CBOR EDN operations,
abstracting the underlying cbor-diag library implementation.
"""

import cbor_diag  # type: ignore[import-untyped]


def cbor_to_diag(cbor_data: bytes) -> str:
    """Convert CBOR data to diagnostic notation.

    Args:
        cbor_data: CBOR encoded bytes

    Returns:
        Diagnostic notation string
    """
    return cbor_diag.cbor2diag(cbor_data)  # type: ignore[no-any-return]


def diag_to_cbor(diag_str: str) -> bytes:
    """Convert diagnostic notation to CBOR data.

    Args:
        diag_str: Diagnostic notation string

    Returns:
        CBOR encoded bytes
    """
    return cbor_diag.diag2cbor(diag_str)  # type: ignore[no-any-return]


def to_diagnostic(cbor_data: bytes) -> str:
    """Alias for cbor_to_diag for compatibility."""
    return cbor_to_diag(cbor_data)


def from_diagnostic(diag_str: str) -> bytes:
    """Alias for diag_to_cbor for compatibility."""
    return diag_to_cbor(diag_str)
