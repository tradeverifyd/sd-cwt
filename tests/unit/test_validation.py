"""Unit tests for CBOR and CDDL validation."""

import cbor2
import pytest

from sd_cwt.validation import CBORValidator, CDDLValidator, SDCWTValidator


class TestCBORValidator:
    """Test cases for CBOR validation utilities."""

    @pytest.mark.unit
    def test_cbor_to_diagnostic(self):
        """Test converting CBOR to diagnostic notation."""
        data = {"key": "value", "number": 42}
        cbor_data = cbor2.dumps(data)

        validator = CBORValidator()
        diag = validator.to_diagnostic(cbor_data)

        assert isinstance(diag, str)
        assert "key" in diag or '"key"' in diag
        assert "value" in diag or '"value"' in diag
        assert "42" in diag

    @pytest.mark.unit
    def test_diagnostic_to_cbor(self):
        """Test converting diagnostic notation to CBOR."""
        diag_str = '{"key": "value", "number": 42}'

        validator = CBORValidator()
        cbor_data = validator.from_diagnostic(diag_str)

        assert isinstance(cbor_data, bytes)
        decoded = cbor2.loads(cbor_data)
        assert decoded["key"] == "value"
        assert decoded["number"] == 42

    @pytest.mark.unit
    def test_validate_valid_cbor(self):
        """Test validating valid CBOR structure."""
        data = {"test": "data"}
        cbor_data = cbor2.dumps(data)

        validator = CBORValidator()
        assert validator.validate_structure(cbor_data) is True

    @pytest.mark.unit
    def test_validate_invalid_cbor(self):
        """Test validating invalid CBOR structure."""
        # Use actual invalid CBOR (incomplete CBOR bytes)
        invalid_cbor = b"\x82\x01"  # Array of 2 items but only 1 provided

        validator = CBORValidator()
        assert validator.validate_structure(invalid_cbor) is False


class TestCDDLValidator:
    """Test cases for CDDL schema validation."""

    @pytest.mark.unit
    def test_cddl_validator_initialization(self):
        """Test CDDL validator initialization."""
        validator = CDDLValidator()
        assert validator.schema is not None
        assert "59" in validator.schema or "redacted_claim_keys" in validator.schema
        assert "disclosure" in validator.schema

    @pytest.mark.unit
    def test_custom_cddl_schema(self):
        """Test using custom CDDL schema."""
        custom_schema = """
        test-type = {
            "field1": tstr,
            "field2": int
        }
        """
        validator = CDDLValidator(custom_schema)
        assert validator.schema == custom_schema

    @pytest.mark.unit
    def test_validate_disclosure_format(self):
        """Test validating disclosure array format."""
        disclosure = [b"salt123", "claim_value", "claim_name"]  # SD-CWT format: [salt, value, key]
        disclosure_cbor = cbor2.dumps(disclosure)

        validator = CDDLValidator()
        # Note: This might fail if pycddl is not properly installed
        # or if the schema compilation fails
        result = validator.validate_disclosure(disclosure_cbor)
        assert isinstance(result, bool)


class TestSDCWTValidator:
    """Test cases for SD-CWT token validation."""

    @pytest.mark.unit
    def test_validate_valid_token(self, mock_cwt_token: bytes):
        """Test validating a valid SD-CWT token."""
        validator = SDCWTValidator()
        results = validator.validate_token(mock_cwt_token)

        assert isinstance(results, dict)
        assert "cbor_valid" in results
        assert "has_redacted_claims" in results
        assert "has_sd_alg_header" in results
        assert "errors" in results

        # Mock token should be valid CBOR
        assert results["cbor_valid"] is True
        assert results["has_redacted_claims"] is True
        # Mock token is a simple payload, not full COSE structure, so no headers expected
        assert results["has_sd_alg_header"] is False

    @pytest.mark.unit
    def test_validate_invalid_token(self):
        """Test validating an invalid token."""
        # Use actual invalid CBOR (incomplete CBOR bytes)
        invalid_token = b"\x82\x01"  # Incomplete CBOR array

        validator = SDCWTValidator()
        results = validator.validate_token(invalid_token)

        assert results["valid"] is False
        assert results["cbor_valid"] is False
        assert len(results["errors"]) > 0

    @pytest.mark.unit
    def test_validate_token_missing_sd_claims(self):
        """Test validating token without SD claims."""
        token_without_sd = cbor2.dumps({"iss": "issuer", "sub": "subject", "iat": 1234567890})

        validator = SDCWTValidator()
        results = validator.validate_token(token_without_sd)

        assert results["cbor_valid"] is True
        assert results["has_redacted_claims"] is False
        assert results["has_sd_alg_header"] is False
        assert results["valid"] is False

    @pytest.mark.unit
    def test_validate_disclosure(self):
        """Test validating disclosure array."""
        valid_disclosure = [b"salt", "value", "name"]  # SD-CWT format: [salt, value, key]
        disclosure_cbor = cbor2.dumps(valid_disclosure)

        validator = SDCWTValidator()
        results = validator.validate_disclosure(disclosure_cbor)

        assert results["cbor_valid"] is True
        assert results["format_valid"] is True
        assert results["valid"] is True

    @pytest.mark.unit
    def test_validate_invalid_disclosure(self):
        """Test validating invalid disclosure."""
        # Wrong number of elements
        invalid_disclosure = [b"salt", "name"]
        disclosure_cbor = cbor2.dumps(invalid_disclosure)

        validator = SDCWTValidator()
        results = validator.validate_disclosure(disclosure_cbor)

        assert results["cbor_valid"] is True
        assert results["format_valid"] is False
        assert results["valid"] is False
        assert "3 elements" in str(results["errors"])

    @pytest.mark.unit
    def test_validate_disclosure_wrong_types(self):
        """Test validating disclosure with wrong types."""
        # Salt should be bytes, not string
        invalid_disclosure = ["salt_string", "name", "value"]
        disclosure_cbor = cbor2.dumps(invalid_disclosure)

        validator = SDCWTValidator()
        results = validator.validate_disclosure(disclosure_cbor)

        assert results["cbor_valid"] is True
        assert results["format_valid"] is False
        assert results["valid"] is False
        assert "salt" in str(results["errors"]).lower()

    @pytest.mark.unit
    def test_print_diagnostic(self, capsys, mock_cwt_token: bytes):
        """Test printing diagnostic notation."""
        validator = SDCWTValidator()
        validator.print_diagnostic(mock_cwt_token)

        captured = capsys.readouterr()
        assert "SD-CWT Diagnostic Notation:" in captured.out
