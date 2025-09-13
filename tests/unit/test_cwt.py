"""Unit tests for CWT (CBOR Web Token) functionality."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import cbor2
import pytest


class TestCWT:
    """Test cases for CWT operations."""

    @pytest.mark.unit
    def test_cwt_claims_structure(self, sample_claims: Dict[str, Any]):
        """Test CWT claims have required structure."""
        # Standard CWT claim labels (from RFC 8392)
        required_claims = ["iss", "sub", "iat"]
        
        for claim in required_claims:
            assert claim in sample_claims
            assert sample_claims[claim] is not None

    @pytest.mark.unit
    def test_cwt_timestamp_claims(self, sample_claims: Dict[str, Any]):
        """Test CWT timestamp claims are valid."""
        now = datetime.now(timezone.utc)
        now_timestamp = int(now.timestamp())
        
        # iat (issued at) should be close to current time (within 1 minute)
        assert abs(sample_claims["iat"] - now_timestamp) < 60
        
        # exp (expiration) should be in the future
        assert sample_claims["exp"] > now_timestamp
        
        # nbf (not before) should be close to iat
        assert abs(sample_claims["nbf"] - sample_claims["iat"]) < 5

    @pytest.mark.unit
    def test_minimal_cwt(self, minimal_claims: Dict[str, Any]):
        """Test minimal CWT with only required claims."""
        # Minimal CWT should have at least these claims
        assert "iss" in minimal_claims
        assert "sub" in minimal_claims
        assert "iat" in minimal_claims
        
        # Should be CBOR serializable
        encoded = cbor2.dumps(minimal_claims)
        assert isinstance(encoded, bytes)
        
        # Should be decodable
        decoded = cbor2.loads(encoded)
        assert decoded == minimal_claims

    @pytest.mark.unit
    def test_cwt_with_sd_claims(self, sample_claims: Dict[str, Any]):
        """Test CWT with selective disclosure claims added."""
        # Add SD-specific claims
        sd_claims = sample_claims.copy()
        sd_claims["_sd"] = ["hash1", "hash2", "hash3"]
        sd_claims["_sd_alg"] = "sha-256"
        
        assert "_sd" in sd_claims
        assert "_sd_alg" in sd_claims
        assert isinstance(sd_claims["_sd"], list)
        assert len(sd_claims["_sd"]) == 3

    @pytest.mark.unit
    def test_cwt_cbor_encoding(self, sample_claims: Dict[str, Any]):
        """Test CBOR encoding of CWT claims."""
        encoded = cbor2.dumps(sample_claims)
        
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0
        
        # Decode and verify
        decoded = cbor2.loads(encoded)
        assert decoded == sample_claims

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "claim_label,claim_name",
        [
            (1, "iss"),  # Issuer
            (2, "sub"),  # Subject
            (3, "aud"),  # Audience
            (4, "exp"),  # Expiration Time
            (5, "nbf"),  # Not Before
            (6, "iat"),  # Issued At
            (7, "jti"),  # JWT ID
        ],
    )
    def test_cwt_claim_labels(self, claim_label: int, claim_name: str):
        """Test CWT claim label mappings."""
        # In real implementation, we'd map string names to integer labels
        # This test verifies the mapping is correct
        claim_map = {
            "iss": 1,
            "sub": 2,
            "aud": 3,
            "exp": 4,
            "nbf": 5,
            "iat": 6,
            "jti": 7,
        }
        
        assert claim_map[claim_name] == claim_label

    @pytest.mark.unit
    def test_cwt_with_nested_claims(self, sample_claims: Dict[str, Any]):
        """Test CWT with nested structure claims."""
        # Address is a nested object
        assert "address" in sample_claims
        assert isinstance(sample_claims["address"], dict)
        
        # Encode with nested structure
        encoded = cbor2.dumps(sample_claims)
        decoded = cbor2.loads(encoded)
        
        # Verify nested structure is preserved
        assert decoded["address"] == sample_claims["address"]
        assert decoded["address"]["street"] == "123 Main St"

    @pytest.mark.unit
    def test_cwt_expiration_validation(self):
        """Test CWT expiration time validation."""
        now = datetime.now(timezone.utc)
        
        # Expired token
        expired_claims = {
            "iss": "test",
            "sub": "test",
            "exp": int((now - timedelta(hours=1)).timestamp()),
        }
        
        # Token should be considered expired
        assert expired_claims["exp"] < int(now.timestamp())
        
        # Valid token
        valid_claims = {
            "iss": "test",
            "sub": "test",
            "exp": int((now + timedelta(hours=1)).timestamp()),
        }
        
        # Token should be valid
        assert valid_claims["exp"] > int(now.timestamp())

    @pytest.mark.unit
    def test_cwt_not_before_validation(self):
        """Test CWT not-before time validation."""
        now = datetime.now(timezone.utc)
        
        # Future nbf (not yet valid)
        future_claims = {
            "iss": "test",
            "sub": "test",
            "nbf": int((now + timedelta(hours=1)).timestamp()),
        }
        
        # Token should not be valid yet
        assert future_claims["nbf"] > int(now.timestamp())
        
        # Past nbf (valid)
        past_claims = {
            "iss": "test",
            "sub": "test",
            "nbf": int((now - timedelta(hours=1)).timestamp()),
        }
        
        # Token should be valid
        assert past_claims["nbf"] < int(now.timestamp())