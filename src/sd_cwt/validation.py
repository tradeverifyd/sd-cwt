from . import cbor_utils
"""CBOR and CDDL validation utilities for SD-CWT."""

from typing import Any, Optional

from . import cddl_utils, edn_utils
from .cddl_schemas import COMBINED_CDDL


class CBORValidator:
    """Utility class for CBOR validation and diagnostics."""

    @staticmethod
    def to_diagnostic(cbor_data: bytes) -> str:
        """Convert CBOR data to diagnostic notation.

        Args:
            cbor_data: CBOR encoded bytes

        Returns:
            Diagnostic notation string
        """
        return edn_utils.cbor_to_diag(cbor_data)

    @staticmethod
    def from_diagnostic(diag_str: str) -> bytes:
        """Convert diagnostic notation to CBOR data.

        Args:
            diag_str: Diagnostic notation string

        Returns:
            CBOR encoded bytes
        """
        return edn_utils.diag_to_cbor(diag_str)

    @staticmethod
    def validate_structure(cbor_data: bytes) -> bool:
        """Validate CBOR structure.

        Args:
            cbor_data: CBOR encoded bytes

        Returns:
            True if valid CBOR structure
        """
        try:
            cbor_utils.decode(cbor_data)
            return True
        except (cbor_utils.CBORDecodeError, ValueError, TypeError):
            return False

    @staticmethod
    def pretty_print(cbor_data: bytes) -> None:
        """Pretty print CBOR data in diagnostic notation.

        Args:
            cbor_data: CBOR encoded bytes
        """
        diag = CBORValidator.to_diagnostic(cbor_data)
        print(diag)


class CDDLValidator:
    """Utility class for CDDL schema validation."""

    # Simplified CDDL schema for zcbor compatibility
    SIMPLE_CDDL = """
    ; Basic COSE Key schema (zcbor-compatible)
    cose-key = {
        1: int,      ; kty (key type) - required
        ? 2: bstr,   ; kid (key ID) - optional
        ? 3: int,    ; alg (algorithm) - optional
        ? -1: int,   ; crv (curve) - for EC keys
        ? -2: bstr,  ; x coordinate - for EC keys
        ? -3: bstr,  ; y coordinate - for EC2 keys
        ? -4: bstr,  ; d (private key) - for private keys
        * int => any
    }

    ; SD-CWT schema (simplified)
    sd-cwt = [
        bstr,  ; protected header
        {},    ; unprotected header
        bstr,  ; payload
        bstr   ; signature
    ]

    ; Disclosure schema
    disclosure = [
        bstr,        ; salt
        any,         ; claim value
        (int / tstr) ; claim key
    ]
    """

    def __init__(self, cddl_schema: Optional[str] = None):
        """Initialize CDDL validator.

        Args:
            cddl_schema: Optional custom CDDL schema string
        """
        self.schema = cddl_schema or self.SIMPLE_CDDL
        self.validator = cddl_utils.create_validator(self.schema)

    def validate(self, cbor_data: bytes, type_name: str = "sd-cwt") -> bool:
        """Validate CBOR data against CDDL schema.

        Args:
            cbor_data: CBOR encoded data to validate
            type_name: CDDL type name to validate against

        Returns:
            True if valid according to schema
        """
        return self.validator.validate(cbor_data, type_name)

    def validate_disclosure(self, disclosure_cbor: bytes) -> bool:
        """Validate a disclosure array.

        Args:
            disclosure_cbor: CBOR encoded disclosure array

        Returns:
            True if valid disclosure format
        """
        return self.validate(disclosure_cbor, "disclosure")


class SDCWTValidator:
    """High-level validator for SD-CWT tokens."""

    def __init__(self) -> None:
        """Initialize SD-CWT validator."""
        self.cbor_validator = CBORValidator()
        self.cddl_validator = CDDLValidator()

    def validate_token(self, token: bytes) -> dict[str, Any]:
        """Validate an SD-CWT token.

        Args:
            token: CBOR encoded SD-CWT token

        Returns:
            Validation results dictionary
        """
        results: dict[str, Any] = {
            "valid": False,
            "cbor_valid": False,
            "cddl_valid": False,
            "has_redacted_claims": False,
            "has_sd_alg_header": False,
            "errors": [],
        }

        # Check CBOR structure
        if not self.cbor_validator.validate_structure(token):
            results["errors"].append("Invalid CBOR structure")
            return results

        results["cbor_valid"] = True

        # Check CDDL compliance
        if not self.cddl_validator.validate(token):
            results["errors"].append("CDDL validation failed")
        else:
            results["cddl_valid"] = True

        # Check for SD-CWT specific claims and headers
        try:
            decoded = cbor_utils.decode(token)
            if isinstance(decoded, list) and len(decoded) >= 4:
                # Extract payload and headers from COSE structure
                payload = cbor_utils.decode(decoded[2])
                protected_header = cbor_utils.decode(decoded[0]) if decoded[0] else {}
                unprotected_header = decoded[1]

                # Check for redacted_claim_keys (simple value 59)
                if 59 in payload:
                    results["has_redacted_claims"] = True
                    if not isinstance(payload[59], list):
                        results["errors"].append("redacted_claim_keys (59) must be an array")

                # Check for sd_alg in protected header (header parameter 18)
                if 18 in protected_header:
                    results["has_sd_alg_header"] = True
                    if not isinstance(protected_header[18], int):
                        results["errors"].append("sd_alg (18) must be an integer")

                # Check for sd_claims in unprotected header (header parameter 17)
                if 17 in unprotected_header and not isinstance(unprotected_header[17], list):
                    results["errors"].append("sd_claims (17) must be an array")
            else:
                payload = decoded
                # Check for redacted_claim_keys (simple value 59) in simple payload
                if 59 in payload:
                    results["has_redacted_claims"] = True
                    if not isinstance(payload[59], list):
                        results["errors"].append("redacted_claim_keys (59) must be an array")

        except Exception as e:
            results["errors"].append(f"Failed to parse token: {e}")

        # Set overall validity
        results["valid"] = results["cbor_valid"] and len(results["errors"]) == 0

        return results

    def validate_disclosure(self, disclosure: bytes) -> dict[str, Any]:
        """Validate a disclosure array.

        Args:
            disclosure: CBOR encoded disclosure

        Returns:
            Validation results dictionary
        """
        results: dict[str, Any] = {
            "valid": False,
            "cbor_valid": False,
            "format_valid": False,
            "errors": [],
        }

        # Check CBOR structure
        if not self.cbor_validator.validate_structure(disclosure):
            results["errors"].append("Invalid CBOR structure")
            return results

        results["cbor_valid"] = True

        # Check disclosure format
        try:
            decoded = cbor_utils.decode(disclosure)
            if not isinstance(decoded, list):
                results["errors"].append("Disclosure must be an array")
            elif len(decoded) != 3:
                results["errors"].append("Disclosure must have exactly 3 elements")
            else:
                # Check element types for SD-CWT format: [salt, value, key]
                if not isinstance(decoded[0], bytes):
                    results["errors"].append("First element (salt) must be bytes")
                # Second element (value) can be any type
                if not isinstance(decoded[2], (str, int)):
                    results["errors"].append("Third element (claim key) must be string or int")
                results["format_valid"] = len(results["errors"]) == 0

        except Exception as e:
            results["errors"].append(f"Failed to parse disclosure: {e}")

        results["valid"] = results["cbor_valid"] and results["format_valid"]
        return results

    def print_diagnostic(self, token: bytes) -> None:
        """Print token in diagnostic notation.

        Args:
            token: CBOR encoded token
        """
        print("SD-CWT Diagnostic Notation:")
        self.cbor_validator.pretty_print(token)
