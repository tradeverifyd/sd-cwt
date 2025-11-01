"""CDDL (Concise Data Definition Language) utilities wrapper.

This module provides a unified interface for CDDL validation operations,
abstracting the underlying zcbor library implementation.
"""

from typing import Any, Optional

import zcbor  # type: ignore[import-untyped]

from . import cbor_utils


class CDDLValidator:
    """CDDL schema validator using zcbor."""

    def __init__(self, schema: str):
        """Initialize with CDDL schema string.

        Args:
            schema: CDDL schema string
        """
        self.schema = schema
        self.validator: Optional[zcbor.DataTranslator] = None
        self._compile_schema()

    def _compile_schema(self) -> None:
        """Compile the CDDL schema."""
        try:
            self.validator = zcbor.DataTranslator.from_cddl(self.schema, default_max_qty=100)
        except Exception as e:
            print(f"Failed to compile CDDL schema with zcbor: {e}")
            self.validator = None

    def validate(self, cbor_data: bytes, type_name: str = "sd-cwt") -> bool:
        """Validate CBOR data against CDDL schema.

        Args:
            cbor_data: CBOR encoded data to validate
            type_name: CDDL type name to validate against

        Returns:
            True if valid according to schema
        """
        if not self.validator:
            return False

        try:
            # Decode CBOR data first
            decoded_data = cbor_utils.decode(cbor_data)

            # Use zcbor to validate the data structure
            type_obj = self.validator.my_types[type_name]
            type_obj.validate_obj(decoded_data)
            return True
        except Exception:
            return False

    def validate_obj(self, obj: Any, type_name: str = "sd-cwt") -> bool:
        """Validate Python object against CDDL schema.

        Args:
            obj: Python object to validate
            type_name: CDDL type name to validate against

        Returns:
            True if valid according to schema
        """
        if not self.validator:
            return False

        try:
            type_obj = self.validator.my_types[type_name]
            type_obj.validate_obj(obj)
            return True
        except Exception:
            return False


def create_validator(schema: str) -> CDDLValidator:
    """Create a CDDL validator instance.

    Args:
        schema: CDDL schema string

    Returns:
        CDDLValidator instance
    """
    return CDDLValidator(schema)


def validate_cbor(cbor_data: bytes, schema: str, type_name: str = "sd-cwt") -> bool:
    """Validate CBOR data against CDDL schema (convenience function).

    Args:
        cbor_data: CBOR encoded data
        schema: CDDL schema string
        type_name: CDDL type name to validate against

    Returns:
        True if valid
    """
    validator = create_validator(schema)
    return validator.validate(cbor_data, type_name)


def validate_object(obj: Any, schema: str, type_name: str = "sd-cwt") -> bool:
    """Validate Python object against CDDL schema (convenience function).

    Args:
        obj: Python object to validate
        schema: CDDL schema string
        type_name: CDDL type name to validate against

    Returns:
        True if valid
    """
    validator = create_validator(schema)
    return validator.validate_obj(obj, type_name)
