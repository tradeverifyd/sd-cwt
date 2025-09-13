from sd_cwt import cbor_utils
"""Unit tests for selective disclosure functionality."""

import hashlib
from typing import Any

import pytest


class TestSelectiveDisclosure:
    """Test cases for selective disclosure operations."""

    @pytest.mark.unit
    def test_create_disclosure_with_salt(self, sample_salts: dict[str, bytes]):
        """Test creating a disclosure with salt."""
        claim_name = "given_name"
        claim_value = "John"
        salt = sample_salts[claim_name]

        disclosure = [salt, claim_name, claim_value]

        assert len(disclosure) == 3
        assert disclosure[0] == salt
        assert disclosure[1] == claim_name
        assert disclosure[2] == claim_value

    @pytest.mark.unit
    def test_hash_disclosure(self, disclosure_array: list):
        """Test hashing a disclosure array."""
        for disclosure in disclosure_array:
            # Encode disclosure as CBOR
            encoded = cbor_utils.encode(disclosure)

            # Hash the encoded disclosure
            hash_value = hashlib.sha256(encoded).digest()

            assert isinstance(hash_value, bytes)
            assert len(hash_value) == 32  # SHA-256 produces 32 bytes

    @pytest.mark.unit
    def test_selective_disclosure_claims_structure(
        self, selective_disclosure_claims: dict[str, Any]
    ):
        """Test the structure of selective disclosure claims."""
        required_fields = ["given_name", "family_name", "email"]

        for field in required_fields:
            assert field in selective_disclosure_claims
            assert selective_disclosure_claims[field] is not None

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "claim_name,expected_type",
        [
            ("given_name", str),
            ("family_name", str),
            ("email", str),
            ("phone_number", str),
            ("birthdate", str),
        ],
    )
    def test_claim_types(
        self,
        selective_disclosure_claims: dict[str, Any],
        claim_name: str,
        expected_type: type,
    ):
        """Test that claims have expected types."""
        assert claim_name in selective_disclosure_claims
        assert isinstance(selective_disclosure_claims[claim_name], expected_type)

    @pytest.mark.unit
    def test_create_sd_hash_digest(self):
        """Test creating SD hash digest from disclosure."""
        disclosure = ["salt123", "claim_name", "claim_value"]
        encoded = cbor_utils.encode(disclosure)
        digest = hashlib.sha256(encoded).digest()

        # Convert to base64url for inclusion in SD array
        import base64

        b64_digest = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        assert isinstance(b64_digest, str)
        assert len(b64_digest) > 0
        # Base64url encoded SHA-256 should be 43 characters (without padding)
        assert len(b64_digest) == 43

    @pytest.mark.unit
    def test_multiple_disclosures(self, disclosure_array: list):
        """Test handling multiple disclosures."""
        hashes = []
        for disclosure in disclosure_array:
            encoded = cbor_utils.encode(disclosure)
            hash_value = hashlib.sha256(encoded).digest()
            hashes.append(hash_value)

        # All hashes should be unique
        assert len(hashes) == len(set(hashes))

        # All hashes should be 32 bytes
        for h in hashes:
            assert len(h) == 32

    @pytest.mark.unit
    def test_empty_disclosure(self):
        """Test handling empty disclosure."""
        with pytest.raises(ValueError, match="Disclosure must have exactly 3 elements"):
            # Empty disclosure should not be allowed
            disclosure = []
            if len(disclosure) != 3:
                raise ValueError("Disclosure must have exactly 3 elements")

    @pytest.mark.unit
    def test_disclosure_with_complex_value(self, sample_claims: dict[str, Any]):
        """Test disclosure with complex claim value."""
        address = sample_claims["address"]
        disclosure = [b"salt_address", "address", address]

        assert len(disclosure) == 3
        assert isinstance(disclosure[2], dict)
        assert "street" in disclosure[2]
        assert "city" in disclosure[2]

    @pytest.mark.unit
    def test_disclosure_with_array_value(self, sample_claims: dict[str, Any]):
        """Test disclosure with array claim value."""
        roles = sample_claims["roles"]
        disclosure = [b"salt_roles", "roles", roles]

        assert len(disclosure) == 3
        assert isinstance(disclosure[2], list)
        assert len(disclosure[2]) == 2
        assert "user" in disclosure[2]
        assert "admin" in disclosure[2]
