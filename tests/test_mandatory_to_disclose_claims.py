from sd_cwt import cbor_utils
"""Tests to verify that mandatory-to-disclose claims are never redacted."""

import pytest

from sd_cwt import SeededSaltGenerator, edn_to_redacted_cbor


class TestMandatoryToDiscloseClaimsRedaction:
    """Test that mandatory-to-disclose claims are never redacted per specification."""

    def test_cnf_claim_protection(self) -> None:
        """Test that cnf claim is never redacted, even with redaction tag."""
        # EDN with cnf claim tagged for redaction (should be ignored)
        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123",
            8: 59({"1": {"kty": 2, "crv": 1}}),
            "email": 59("alice@example.com")
        }
        """

        # Process with deterministic salt
        seeded_gen = SeededSaltGenerator(seed=42)
        cbor_claims, disclosures = edn_to_redacted_cbor(edn_claims, seeded_gen)

        # Parse claims
        claims = cbor_utils.decode(cbor_claims)

        # cnf claim (8) should still be present - not redacted
        assert 8 in claims, "cnf claim must never be redacted"
        assert claims[8] == {"1": {"kty": 2, "crv": 1}}, "cnf claim should be preserved exactly"

        # Only email should be redacted
        assert len(disclosures) == 1, "Only non-mandatory-to-disclose claims should be redacted"

        # Decode the disclosure to verify it's the email
        disclosure = cbor_utils.decode(disclosures[0])
        assert disclosure[2] == "email", "Only email should be disclosed"

    def test_standard_claims_protection(self) -> None:
        """Test that standard claims are never redacted."""
        edn_claims = """
        {
            1: 59("https://issuer.example"),    # iss - should not be redacted
            2: "user123",                       # sub - can be redacted
            3: 59("https://verifier.example"),  # aud - should not be redacted
            4: 59(1756656000),                  # exp - should not be redacted
            5: 59(1725244200),                  # nbf - should not be redacted
            6: 59(1725330600),                  # iat - should not be redacted
            7: 59("unique-id-123"),             # cti - should not be redacted
            39: 59(h'deadbeef'),                # cnonce - should not be redacted
            "custom": 59("custom_value")        # custom claim - should be redacted
        }
        """

        seeded_gen = SeededSaltGenerator(seed=123)
        cbor_claims, disclosures = edn_to_redacted_cbor(edn_claims, seeded_gen)

        claims = cbor_utils.decode(cbor_claims)

        # All standard claims should be preserved
        assert 1 in claims, "iss claim must not be redacted"
        assert claims[1] == "https://issuer.example"

        assert 2 in claims, "sub claim is present (not tagged for redaction)"
        assert claims[2] == "user123"

        assert 3 in claims, "aud claim must not be redacted"
        assert claims[3] == "https://verifier.example"

        assert 4 in claims, "exp claim must not be redacted"
        assert claims[4] == 1756656000

        assert 5 in claims, "nbf claim must not be redacted"
        assert claims[5] == 1725244200

        assert 6 in claims, "iat claim must not be redacted"
        assert claims[6] == 1725330600

        assert 7 in claims, "cti claim must not be redacted"
        assert claims[7] == "unique-id-123"

        assert 39 in claims, "cnonce claim must not be redacted"
        assert claims[39] == b'\xde\xad\xbe\xef'

        # Only custom claim should be redacted
        assert len(disclosures) == 1, "Only custom claim should be redacted"
        disclosure = cbor_utils.decode(disclosures[0])
        assert disclosure[2] == "custom", "Custom claim should be disclosed"

    def test_all_protected_claims_list(self) -> None:
        """Test comprehensive list of protected claims."""
        # Test that attempting to redact all protected claims results in no redactions
        edn_claims = """
        {
            1: 59("issuer"),      # iss
            3: 59("audience"),    # aud
            4: 59(9999999),       # exp
            5: 59(1111111),       # nbf
            6: 59(2222222),       # iat
            7: 59("cti_value"),   # cti
            8: 59({"test": "cnf"}), # cnf
            39: 59("nonce")       # cnonce
        }
        """

        cbor_claims, disclosures = edn_to_redacted_cbor(edn_claims)
        claims = cbor_utils.decode(cbor_claims)

        # No claims should be redacted
        assert len(disclosures) == 0, "No mandatory-to-disclose claims should be redacted"

        # All claims should be preserved
        expected_claims = {
            1: "issuer",
            3: "audience",
            4: 9999999,
            5: 1111111,
            6: 2222222,
            7: "cti_value",
            8: {"test": "cnf"},
            39: "nonce"
        }

        for key, expected_value in expected_claims.items():
            assert key in claims, f"Mandatory-to-disclose claim {key} should be preserved"
            assert claims[key] == expected_value, f"Mandatory-to-disclose claim {key} value should match"

    def test_subject_can_be_redacted(self) -> None:
        """Test that subject claim can be redacted (it's the exception)."""
        edn_claims = """
        {
            1: "https://issuer.example",
            2: 59("alice@example.com"),  # sub - can be redacted
            "name": 59("Alice Smith")
        }
        """

        cbor_claims, disclosures = edn_to_redacted_cbor(edn_claims)
        claims = cbor_utils.decode(cbor_claims)

        # Subject should be redacted
        assert 2 not in claims, "Subject claim should be redacted when tagged"

        # Should have 2 disclosures: sub and name
        assert len(disclosures) == 2, "Both sub and name should be redacted"

        # Verify both disclosures
        disclosure_names = []
        for disclosure_bytes in disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            disclosure_names.append(disclosure[2])

        assert 2 in disclosure_names, "Subject claim should be in disclosures"
        assert "name" in disclosure_names, "Name claim should be in disclosures"

    def test_nested_mandatory_to_disclose_claims(self) -> None:
        """Test that mandatory-to-disclose protection only applies to top-level claims."""
        # Test nested structures where mandatory-to-disclose claim numbers appear
        # at non-top-level - these should be redactable
        edn_claims = """
        {
            1: "https://issuer.example",     # Top-level iss - mandatory to disclose
            "nested": {
                1: 59("nested_iss_value"),   # Nested "1" - should be redactable
                8: 59("nested_cnf_value")    # Nested "8" - should be redactable
            },
            "array_test": [
                59({"1": "in_array"}),       # In array - should be redactable
                59({"8": "also_in_array"})   # In array - should be redactable
            ]
        }
        """

        cbor_claims, disclosures = edn_to_redacted_cbor(edn_claims)
        claims = cbor_utils.decode(cbor_claims)

        # Top-level iss should be preserved
        assert 1 in claims, "Top-level iss should be mandatory to disclose"
        assert claims[1] == "https://issuer.example"

        # Should have disclosures for nested and array elements
        assert len(disclosures) > 0, "Nested mandatory-to-disclose claim numbers should be redactable"

        # Nested structure should have redacted items
        nested = claims["nested"]
        assert 1 not in nested, "Nested '1' should be redacted"
        assert 8 not in nested, "Nested '8' should be redacted"