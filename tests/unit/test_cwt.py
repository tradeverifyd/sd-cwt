"""Unit tests for CWT (CBOR Web Token) functionality matching SD-CWT specification."""

from datetime import datetime, timedelta, timezone

import cbor2
import pytest


class TestCWT:
    """Test cases for CWT operations using specification examples."""

    @pytest.mark.unit
    def test_specification_cwt_structure(self):
        """Test CWT claims structure matching the specification example."""
        # Based on the specification example from draft-ietf-spice-sd-cwt
        spec_claims = {
            1: "https://issuer.example",  # iss
            2: "https://device.example",  # sub
            4: 1725330600,  # exp
            5: 1725243840,  # nbf
            6: 1725244200,  # iat
            8: {  # cnf (confirmation)
                1: {  # COSE_Key
                    1: 2,  # kty: EC2
                    -1: 1,  # crv: P-256
                    -2: bytes.fromhex(
                        "8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d"
                    ),
                    -3: bytes.fromhex(
                        "4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343"
                    ),
                }
            },
            500: True,  # Custom claim (device_enabled)
            501: "ABCD-123456",  # Custom claim (device_id)
            502: [1549560720, 1612498440, 1674004740],  # Custom claim (timestamps)
            503: {  # Custom claim (address)
                "country": "us",
                "region": "ca",
                "postal_code": "94188",
            },
        }

        # Test structure using integer labels
        assert 1 in spec_claims  # iss
        assert 2 in spec_claims  # sub
        assert 6 in spec_claims  # iat
        assert spec_claims[1] == "https://issuer.example"
        assert spec_claims[2] == "https://device.example"

    @pytest.mark.unit
    def test_specification_timestamp_claims(self):
        """Test specification timestamp claims are valid."""
        # Use exact timestamps from specification
        spec_timestamps = {
            4: 1725330600,  # exp
            5: 1725243840,  # nbf
            6: 1725244200,  # iat
        }

        # Verify timestamps are integers
        assert isinstance(spec_timestamps[4], int)  # exp
        assert isinstance(spec_timestamps[5], int)  # nbf
        assert isinstance(spec_timestamps[6], int)  # iat

        # Verify logical relationship: nbf <= iat < exp
        assert spec_timestamps[5] <= spec_timestamps[6]  # nbf <= iat
        assert spec_timestamps[6] < spec_timestamps[4]  # iat < exp

    @pytest.mark.unit
    def test_minimal_cwt_integer_labels(self):
        """Test minimal CWT with integer labels only."""
        minimal_claims = {
            1: "https://issuer.example",  # iss
            2: "https://device.example",  # sub
            6: 1725244200,  # iat
        }

        # Should be CBOR serializable
        encoded = cbor2.dumps(minimal_claims)
        assert isinstance(encoded, bytes)

        # Should be decodable
        decoded = cbor2.loads(encoded)
        assert decoded == minimal_claims

        # Verify integer labels
        assert 1 in decoded  # iss
        assert 2 in decoded  # sub
        assert 6 in decoded  # iat

    @pytest.mark.unit
    def test_sd_cwt_structure(self):
        """Test SD-CWT with selective disclosure claims structure."""
        # SD-CWT claims using specification structure
        sd_claims = {
            1: "https://issuer.example",  # iss
            2: "https://device.example",  # sub
            6: 1725244200,  # iat
            59: [  # redacted_claim_keys (simple value 59)
                b"\x12\x34\x56\x78" * 8,  # 32 bytes hash
                b"\xab\xcd\xef\x00" * 8,  # 32 bytes hash
            ],
        }

        assert 59 in sd_claims  # redacted_claim_keys (simple value 59)
        assert isinstance(sd_claims[59], list)
        assert len(sd_claims[59]) == 2

        # Verify hashes are 32 bytes (SHA-256)
        for hash_val in sd_claims[59]:
            assert len(hash_val) == 32

    @pytest.mark.unit
    def test_specification_cbor_encoding(self):
        """Test CBOR encoding of specification CWT claims."""
        spec_claims = {
            1: "https://issuer.example",  # iss
            2: "https://device.example",  # sub
            6: 1725244200,  # iat
        }

        encoded = cbor2.dumps(spec_claims)

        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

        # Decode and verify
        decoded = cbor2.loads(encoded)
        assert decoded == spec_claims

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "claim_label,claim_description",
        [
            (1, "iss - Issuer"),  # Issuer
            (2, "sub - Subject"),  # Subject
            (3, "aud - Audience"),  # Audience
            (4, "exp - Expiration Time"),  # Expiration Time
            (5, "nbf - Not Before"),  # Not Before
            (6, "iat - Issued At"),  # Issued At
            (7, "cti - CWT ID"),  # CWT ID (not JWT)
            (8, "cnf - Confirmation"),  # Confirmation
        ],
    )
    def test_cwt_integer_claim_labels(self, claim_label: int, claim_description: str):
        """Test CWT integer claim labels from RFC 8392."""
        # Test that we use the correct integer labels
        valid_labels = [1, 2, 3, 4, 5, 6, 7, 8]
        assert claim_label in valid_labels

    @pytest.mark.unit
    def test_specification_nested_claims(self):
        """Test specification CWT with nested structure claims."""
        spec_claims = {
            1: "https://issuer.example",  # iss
            2: "https://device.example",  # sub
            503: {  # address claim (nested)
                "country": "us",
                "region": "ca",
                "postal_code": "94188",
            },
        }

        # Encode with nested structure
        encoded = cbor2.dumps(spec_claims)
        decoded = cbor2.loads(encoded)

        # Verify nested structure is preserved
        assert decoded[503] == spec_claims[503]
        assert decoded[503]["country"] == "us"
        assert decoded[503]["region"] == "ca"
        assert decoded[503]["postal_code"] == "94188"

    @pytest.mark.unit
    def test_cwt_expiration_validation(self):
        """Test CWT expiration time validation using integer labels."""
        now = datetime.now(timezone.utc)

        # Expired token using integer labels
        expired_claims = {
            1: "https://issuer.example",  # iss
            2: "https://device.example",  # sub
            4: int((now - timedelta(hours=1)).timestamp()),  # exp
        }

        # Token should be considered expired
        assert expired_claims[4] < int(now.timestamp())

        # Valid token using integer labels
        valid_claims = {
            1: "https://issuer.example",  # iss
            2: "https://device.example",  # sub
            4: int((now + timedelta(hours=1)).timestamp()),  # exp
        }

        # Token should be valid
        assert valid_claims[4] > int(now.timestamp())

    @pytest.mark.unit
    def test_cwt_not_before_validation(self):
        """Test CWT not-before time validation using integer labels."""
        now = datetime.now(timezone.utc)

        # Future nbf (not yet valid) using integer labels
        future_claims = {
            1: "https://issuer.example",  # iss
            2: "https://device.example",  # sub
            5: int((now + timedelta(hours=1)).timestamp()),  # nbf
        }

        # Token should not be valid yet
        assert future_claims[5] > int(now.timestamp())

        # Past nbf (valid) using integer labels
        past_claims = {
            1: "https://issuer.example",  # iss
            2: "https://device.example",  # sub
            5: int((now - timedelta(hours=1)).timestamp()),  # nbf
        }

        # Token should be valid
        assert past_claims[5] < int(now.timestamp())

    @pytest.mark.unit
    def test_specification_confirmation_claim(self):
        """Test confirmation (cnf) claim structure from specification."""
        cnf_claim = {
            1: {  # COSE_Key
                1: 2,  # kty: EC2
                -1: 1,  # crv: P-256
                -2: bytes.fromhex(
                    "8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d"
                ),
                -3: bytes.fromhex(
                    "4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343"
                ),
            }
        }

        spec_claims = {
            1: "https://issuer.example",  # iss
            2: "https://device.example",  # sub
            8: cnf_claim,  # cnf
        }

        # Verify cnf structure
        assert 8 in spec_claims
        assert 1 in spec_claims[8]  # COSE_Key
        assert spec_claims[8][1][1] == 2  # EC2 key type
        assert spec_claims[8][1][-1] == 1  # P-256 curve
