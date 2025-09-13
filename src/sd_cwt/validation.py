"""CBOR and CDDL validation utilities for SD-CWT."""

from typing import Any, Dict, Optional, Union

import cbor2
import cbor_diag
import pycddl


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
        return cbor_diag.cbor2diag(cbor_data)

    @staticmethod
    def from_diagnostic(diag_str: str) -> bytes:
        """Convert diagnostic notation to CBOR data.
        
        Args:
            diag_str: Diagnostic notation string
            
        Returns:
            CBOR encoded bytes
        """
        return cbor_diag.diag2cbor(diag_str)

    @staticmethod
    def validate_structure(cbor_data: bytes) -> bool:
        """Validate CBOR structure.
        
        Args:
            cbor_data: CBOR encoded bytes
            
        Returns:
            True if valid CBOR structure
        """
        try:
            cbor2.loads(cbor_data)
            return True
        except (cbor2.CBORDecodeError, ValueError, TypeError):
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

    # SD-CWT CDDL schema based on draft-ietf-spice-sd-cwt-04
    SD_CWT_CDDL = """
    sd-cwt = [
        protected: bstr .cbor protected-header,
        unprotected: unprotected-header,
        payload: bstr .cbor sd-cwt-claims,
        signature: bstr
    ]
    
    protected-header = {
        1: int,  ; alg
        * int => any
    }
    
    unprotected-header = {
        * int => any
    }
    
    sd-cwt-claims = {
        1: tstr,  ; iss
        2: tstr,  ; sub
        6: int,   ; iat
        "_sd": [* bstr],  ; selective disclosure digests
        "_sd_alg": tstr,  ; hash algorithm
        * int => any,
        * tstr => any
    }
    
    disclosure = [
        bstr,  ; salt
        tstr,  ; claim name
        any    ; claim value
    ]
    """

    def __init__(self, cddl_schema: Optional[str] = None):
        """Initialize CDDL validator.
        
        Args:
            cddl_schema: Optional custom CDDL schema string
        """
        self.schema = cddl_schema or self.SD_CWT_CDDL
        self.validator = None
        self._compile_schema()

    def _compile_schema(self) -> None:
        """Compile the CDDL schema."""
        try:
            self.validator = pycddl.Schema(self.schema)
        except Exception as e:
            print(f"Failed to compile CDDL schema: {e}")
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
            self.validator.validate_cbor(cbor_data, type_name)
            return True
        except Exception:
            return False

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

    def __init__(self):
        """Initialize SD-CWT validator."""
        self.cbor_validator = CBORValidator()
        self.cddl_validator = CDDLValidator()

    def validate_token(self, token: bytes) -> Dict[str, Any]:
        """Validate an SD-CWT token.
        
        Args:
            token: CBOR encoded SD-CWT token
            
        Returns:
            Validation results dictionary
        """
        results = {
            "valid": False,
            "cbor_valid": False,
            "cddl_valid": False,
            "has_sd_claim": False,
            "has_sd_alg": False,
            "errors": []
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

        # Check for SD-CWT specific claims
        try:
            decoded = cbor2.loads(token)
            if isinstance(decoded, list) and len(decoded) >= 3:
                # Extract payload from COSE structure
                payload = cbor2.loads(decoded[2])
            else:
                payload = decoded

            if "_sd" in payload:
                results["has_sd_claim"] = True
                if not isinstance(payload["_sd"], list):
                    results["errors"].append("_sd claim must be an array")

            if "_sd_alg" in payload:
                results["has_sd_alg"] = True
                if not isinstance(payload["_sd_alg"], str):
                    results["errors"].append("_sd_alg must be a string")

        except Exception as e:
            results["errors"].append(f"Failed to parse token: {e}")

        # Set overall validity
        results["valid"] = (
            results["cbor_valid"] and
            results["has_sd_claim"] and
            results["has_sd_alg"] and
            len(results["errors"]) == 0
        )

        return results

    def validate_disclosure(self, disclosure: bytes) -> Dict[str, Any]:
        """Validate a disclosure array.
        
        Args:
            disclosure: CBOR encoded disclosure
            
        Returns:
            Validation results dictionary
        """
        results = {
            "valid": False,
            "cbor_valid": False,
            "format_valid": False,
            "errors": []
        }

        # Check CBOR structure
        if not self.cbor_validator.validate_structure(disclosure):
            results["errors"].append("Invalid CBOR structure")
            return results
        
        results["cbor_valid"] = True

        # Check disclosure format
        try:
            decoded = cbor2.loads(disclosure)
            if not isinstance(decoded, list):
                results["errors"].append("Disclosure must be an array")
            elif len(decoded) != 3:
                results["errors"].append("Disclosure must have exactly 3 elements")
            else:
                # Check element types
                if not isinstance(decoded[0], bytes):
                    results["errors"].append("First element (salt) must be bytes")
                if not isinstance(decoded[1], str):
                    results["errors"].append("Second element (claim name) must be string")
                # Third element can be any type
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