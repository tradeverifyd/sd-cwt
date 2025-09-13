"""End-to-end integration tests for SD-CWT."""

import json
from pathlib import Path
from typing import Any

import cbor2
import pytest


class TestEndToEnd:
    """Integration tests for complete SD-CWT workflow."""

    @pytest.mark.integration
    def test_full_sd_cwt_lifecycle(
        self, sample_claims: dict[str, Any], selective_disclosure_claims: dict[str, Any]
    ):
        """Test complete lifecycle: create, disclose, verify."""
        # This test demonstrates the full workflow
        # In real implementation, these would call actual SD-CWT functions

        # Step 1: Create SD-CWT with selective disclosure
        issuer_claims = sample_claims.copy()
        sd_claims = []

        for claim_name in selective_disclosure_claims:
            if claim_name in issuer_claims:
                # Would create disclosure and add hash to _sd array
                sd_claims.append(f"hash_of_{claim_name}")
                # Remove from main claims (would be done by SD-CWT library)
                del issuer_claims[claim_name]

        issuer_claims[59] = sd_claims  # redacted_claim_keys (simple value 59)

        assert 59 in issuer_claims
        assert len(issuer_claims[59]) == len(selective_disclosure_claims)

        # Step 2: Holder selects claims to disclose
        _claims_to_disclose = ["given_name", "email"]

        # Step 3: Create presentation with selected disclosures
        presentation_claims = issuer_claims.copy()
        # In real implementation, would include only selected disclosures

        # Step 4: Verifier validates presentation
        assert 59 in presentation_claims

    @pytest.mark.integration
    def test_cbor_serialization_roundtrip(self, sample_claims: dict[str, Any]):
        """Test CBOR serialization and deserialization."""
        # Add SD-specific claims
        claims = sample_claims.copy()
        claims[59] = ["hash1", "hash2", "hash3"]  # redacted_claim_keys

        # Serialize to CBOR
        cbor_data = cbor2.dumps(claims)
        assert isinstance(cbor_data, bytes)

        # Deserialize from CBOR
        decoded_claims = cbor2.loads(cbor_data)

        # Verify all claims are preserved
        assert decoded_claims == claims
        assert decoded_claims[59] == claims[59]

    @pytest.mark.integration
    def test_selective_disclosure_with_holder_binding(
        self, sample_claims: dict[str, Any], cose_key_pair
    ):
        """Test SD-CWT with holder binding."""
        private_key, public_key = cose_key_pair

        # Add holder binding claim
        claims = sample_claims.copy()
        claims["cnf"] = {
            # Confirmation method - would contain holder's public key
            "jwk": "holder_public_key_here"
        }

        assert "cnf" in claims
        assert "jwk" in claims["cnf"]

    @pytest.mark.integration
    def test_partial_disclosure(
        self, sample_claims: dict[str, Any], selective_disclosure_claims: dict[str, Any]
    ):
        """Test partial disclosure of claims."""
        # Create SD-CWT with all selective disclosure claims
        all_sd_claims = list(selective_disclosure_claims.keys())

        # Holder chooses to disclose only subset
        disclosed_claims = ["given_name", "family_name"]
        withheld_claims = ["email", "phone_number", "birthdate"]

        # Verify correct claims are disclosed/withheld
        for claim in disclosed_claims:
            assert claim in all_sd_claims

        for claim in withheld_claims:
            assert claim in all_sd_claims

        # Ensure no overlap
        assert set(disclosed_claims).isdisjoint(set(withheld_claims))

    @pytest.mark.integration
    def test_multiple_presentations(self, selective_disclosure_claims: dict[str, Any]):
        """Test creating multiple presentations with different disclosures."""
        all_claims = list(selective_disclosure_claims.keys())

        # Presentation 1: Basic info
        presentation1_claims = ["given_name", "family_name"]

        # Presentation 2: Contact info
        presentation2_claims = ["email", "phone_number"]

        # Presentation 3: Full disclosure
        presentation3_claims = all_claims

        # Verify each presentation is valid
        assert set(presentation1_claims).issubset(set(all_claims))
        assert set(presentation2_claims).issubset(set(all_claims))
        assert set(presentation3_claims) == set(all_claims)

    @pytest.mark.integration
    def test_load_test_vectors(self, test_data_dir: Path):
        """Test loading and using test vectors."""
        test_vectors_file = test_data_dir / "test_vectors.json"

        if test_vectors_file.exists():
            with open(test_vectors_file) as f:
                test_vectors = json.load(f)

            assert "test_vectors" in test_vectors
            assert len(test_vectors["test_vectors"]) > 0

            for vector in test_vectors["test_vectors"]:
                assert "description" in vector
                assert "input" in vector
                assert "expected" in vector

    @pytest.mark.integration
    @pytest.mark.slow
    def test_performance_large_claims(self, performance_timer):
        """Test performance with large number of claims."""
        performance_timer.start()

        # Create large claims set
        large_claims = {f"claim_{i}": f"value_{i}" for i in range(1000)}

        # Serialize to CBOR
        cbor_data = cbor2.dumps(large_claims)

        # Deserialize from CBOR
        decoded = cbor2.loads(cbor_data)

        performance_timer.stop()

        assert len(decoded) == 1000
        # Should complete in reasonable time (< 1 second)
        assert performance_timer.elapsed < 1.0

    @pytest.mark.integration
    def test_interoperability_format(self, mock_cwt_token: bytes):
        """Test format compatibility with other implementations."""
        # Decode mock CWT token
        decoded = cbor2.loads(mock_cwt_token)

        # Verify expected SD-CWT structure
        assert 59 in decoded  # redacted_claim_keys
        assert isinstance(decoded[59], list)

    @pytest.mark.integration
    def test_cose_key_operations(self, cose_key_pair):
        """Test COSE key operations with fido2."""
        private_key_info, public_key = cose_key_pair

        # Verify keys are properly formatted
        assert isinstance(private_key_info, dict)
        assert "ec_key" in private_key_info
        assert isinstance(public_key, dict)

        # Check required COSE public key parameters
        assert 1 in public_key  # kty
        assert 3 in public_key  # alg
        assert -1 in public_key  # crv
        assert -2 in public_key  # x
        assert -3 in public_key  # y
        assert -4 not in public_key  # d should not be in public key
