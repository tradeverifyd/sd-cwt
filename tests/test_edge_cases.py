from sd_cwt import cbor_utils
"""Tests for SD-CWT edge cases and mandatory-to-disclose claim protections."""

import time

import pytest

from sd_cwt import (
    SeededSaltGenerator,
    cose_key_generate,
    cose_key_to_dict,
    create_sd_cwt_with_holder_binding,
    create_sd_cwt_presentation,
    validate_sd_cwt_presentation,
    edn_to_redacted_cbor,
)
from sd_cwt.cose_sign1 import ES256Signer
from sd_cwt.holder_binding import validate_sd_cwt_cnf


class TestZeroDisclosureEdgeCases:
    """Test SD-CWT with zero disclosures."""

    def test_sd_cwt_with_no_redacted_claims(self) -> None:
        """Test SD-CWT creation when no claims are marked for redaction."""
        # Generate issuer key
        issuer_key = cose_key_generate()
        issuer_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_dict[-4])

        # EDN with NO redaction tags - all claims are public
        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123",
            4: 1725330600,
            5: 1725243840,
            6: 1725244200,
            "role": "admin",
            "department": "engineering",
            "clearance_level": 3
        }
        """

        # Create SD-CWT
        result = create_sd_cwt_with_holder_binding(edn_claims, issuer_signer)

        # Should still work, but with zero disclosures
        assert "sd_cwt" in result
        assert "disclosures" in result
        assert "holder_key" in result
        assert len(result["disclosures"]) == 0  # No redacted claims

        # Decode and verify structure
        sd_cwt = result["sd_cwt"]
        decoded = cbor_utils.decode(sd_cwt)
        payload = cbor_utils.decode(cbor_utils.get_tag_value(decoded)[2])

        # Verify all public claims are present
        assert payload[1] == "https://issuer.example"
        assert payload[2] == "user123"
        assert payload["role"] == "admin"
        assert payload["department"] == "engineering"

        # Verify cnf claim is still mandatory
        assert validate_sd_cwt_cnf(payload) is True

        # Simple value 59 should not be present (no redacted claims)
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 not in payload

    def test_presentation_with_zero_disclosures(self) -> None:
        """Test creating presentation when there are no disclosures."""
        # Setup
        issuer_key = cose_key_generate()
        issuer_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_dict[-4])

        # EDN with no redaction
        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123",
            "status": "active"
        }
        """

        result = create_sd_cwt_with_holder_binding(edn_claims, issuer_signer)
        holder_dict = cose_key_to_dict(result["holder_key"])
        holder_signer = ES256Signer(holder_dict[-4])

        # Create presentation with empty disclosures list
        presentation = create_sd_cwt_presentation(
            result["sd_cwt"],
            result["disclosures"],  # Empty list
            [],  # No indices to select
            holder_signer,
            "https://verifier.example",
            int(time.time())
        )

        # Validate presentation
        validation_result = validate_sd_cwt_presentation(presentation)
        assert validation_result["valid"] is True
        assert len(validation_result["disclosures"]) == 0


class TestAllRedactedEdgeCases:
    """Test SD-CWT with maximum redaction (all non-mandatory claims)."""

    def test_all_optional_claims_redacted(self) -> None:
        """Test SD-CWT with all optional claims redacted, keeping mandatory ones."""
        issuer_key = cose_key_generate()
        issuer_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_dict[-4])

        # EDN where all optional claims are redacted
        # Keep mandatory claims: iss, sub (and cnf will be added automatically)
        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123",
            4: 1725330600,

            "name": 59("Alice Smith"),
            "email": 59("alice@example.com"),
            "phone": 59("555-0123"),
            "address": 59("123 Main St"),
            "ssn": 59("123-45-6789"),
            "salary": 59(75000),
            "manager": 59("Bob Johnson"),
            "project": 59("Secret Project X")
        }
        """

        result = create_sd_cwt_with_holder_binding(edn_claims, issuer_signer)

        # Should have many disclosures
        assert len(result["disclosures"]) == 8  # All redacted claims

        # Decode and verify only mandatory/non-redacted claims remain
        sd_cwt = result["sd_cwt"]
        decoded = cbor_utils.decode(sd_cwt)
        payload = cbor_utils.decode(cbor_utils.get_tag_value(decoded)[2])

        # Mandatory claims should be present
        assert payload[1] == "https://issuer.example"  # iss
        assert payload[2] == "user123"  # sub
        assert payload[4] == 1725330600  # exp

        # cnf claim should be present (mandatory for holder binding)
        assert validate_sd_cwt_cnf(payload) is True

        # All redacted claims should be absent
        redacted_claims = ["name", "email", "phone", "address", "ssn", "salary", "manager", "project"]
        for claim in redacted_claims:
            assert claim not in payload

        # Simple value 59 should contain 8 hashes
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in payload
        assert len(payload[simple_59]) == 8

    def test_selective_disclosure_from_all_redacted(self) -> None:
        """Test selective disclosure when all optional claims are redacted."""
        issuer_key = cose_key_generate()
        issuer_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_dict[-4])

        # Many redacted claims
        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123",

            "claim1": 59("value1"),
            "claim2": 59("value2"),
            "claim3": 59("value3"),
            "claim4": 59("value4"),
            "claim5": 59("value5")
        }
        """

        result = create_sd_cwt_with_holder_binding(
            edn_claims, issuer_signer, salt_generator=SeededSaltGenerator(seed=42)
        )
        holder_dict = cose_key_to_dict(result["holder_key"])
        holder_signer = ES256Signer(holder_dict[-4])

        # Create presentation revealing only claims 1 and 3
        selected_indices = [0, 2]  # First and third claims
        presentation = create_sd_cwt_presentation(
            result["sd_cwt"],
            result["disclosures"],
            selected_indices,
            holder_signer,
            "https://verifier.example",
            int(time.time())
        )

        # Validate
        validation_result = validate_sd_cwt_presentation(presentation)
        assert validation_result["valid"] is True
        assert len(validation_result["disclosures"]) == 2

        # Check disclosed claims
        disclosed_claims = {}
        for disclosure in validation_result["disclosures"]:
            decoded = cbor_utils.decode(disclosure)
            disclosed_claims[decoded[2]] = decoded[1]  # claim_name: claim_value

        assert "claim1" in disclosed_claims
        assert "claim3" in disclosed_claims
        assert disclosed_claims["claim1"] == "value1"
        assert disclosed_claims["claim3"] == "value3"


class TestMandatoryToDiscloseClaimProtection:
    """Test that mandatory-to-disclose claims can never be redacted."""

    def test_cnf_claim_always_present(self) -> None:
        """Test that cnf claim is always present and never redacted."""
        issuer_key = cose_key_generate()
        issuer_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_dict[-4])

        # Try various EDN configurations
        test_cases = [
            '{"test": 59("value")}',  # Minimal
            '{"a": 59("1"), "b": 59("2"), "c": 59("3")}',  # All redacted
            '{"iss": "test", "sub": "user", "exp": 123456789}',  # Standard claims
        ]

        for edn_claims in test_cases:
            result = create_sd_cwt_with_holder_binding(edn_claims, issuer_signer)

            # Decode and verify cnf is always present
            sd_cwt = result["sd_cwt"]
            decoded = cbor_utils.decode(sd_cwt)
            payload = cbor_utils.decode(cbor_utils.get_tag_value(decoded)[2])

            assert validate_sd_cwt_cnf(payload), f"cnf claim missing in: {edn_claims}"
            assert 8 in payload, f"cnf claim (8) not found in: {edn_claims}"

    def test_mandatory_to_disclose_claims_not_redacted(self) -> None:
        """Test that mandatory-to-disclose CWT claims are not redacted per spec."""
        issuer_key = cose_key_generate()
        issuer_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_dict[-4])

        # EDN with standard claims and redacted custom claims
        # Per spec: iss, aud, exp, nbf, iat, cti, cnf, cnonce are mandatory to disclose
        edn_claims = """
        {
            1: "https://issuer.example",
            2: "subject123",
            3: "https://verifier.example",
            4: 1725330600,
            5: 1725243840,
            6: 1725244200,
            7: h'0123456789abcdef0123456789abcdef',
            39: h'636e6f6e636531323334353637383930',

            "custom_claim": 59("redacted_value")
        }
        """

        result = create_sd_cwt_with_holder_binding(edn_claims, issuer_signer)

        # Decode and verify standard claims are present
        sd_cwt = result["sd_cwt"]
        decoded = cbor_utils.decode(sd_cwt)
        payload = cbor_utils.decode(cbor_utils.get_tag_value(decoded)[2])

        # Mandatory-to-disclose claims should be present and not redacted
        assert payload[1] == "https://issuer.example"  # iss
        assert payload[2] == "subject123"  # sub
        assert payload[3] == "https://verifier.example"  # aud
        assert payload[4] == 1725330600  # exp
        assert payload[5] == 1725243840  # nbf
        assert payload[6] == 1725244200  # iat
        assert payload[7] == bytes.fromhex('0123456789abcdef0123456789abcdef')  # cti
        assert payload[39] == bytes.fromhex('636e6f6e636531323334353637383930')  # cnonce

        # cnf should be present (added automatically)
        assert validate_sd_cwt_cnf(payload)

        # Only custom claim should be redacted
        assert "custom_claim" not in payload
        assert len(result["disclosures"]) == 1


class TestEmptyPresentationEdgeCases:
    """Test edge cases with empty or minimal presentations."""

    def test_presentation_with_no_selected_disclosures(self) -> None:
        """Test presentation where holder selects no disclosures to reveal."""
        issuer_key = cose_key_generate()
        issuer_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_dict[-4])

        # EDN with multiple redacted claims
        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123",
            "secret1": 59("top_secret"),
            "secret2": 59("classified"),
            "secret3": 59("confidential")
        }
        """

        result = create_sd_cwt_with_holder_binding(edn_claims, issuer_signer)
        holder_dict = cose_key_to_dict(result["holder_key"])
        holder_signer = ES256Signer(holder_dict[-4])

        # Create presentation with NO disclosures selected
        presentation = create_sd_cwt_presentation(
            result["sd_cwt"],
            result["disclosures"],
            [],  # Select no disclosures
            holder_signer,
            "https://verifier.example",
            int(time.time())
        )

        # Validate - should be valid but reveal nothing
        validation_result = validate_sd_cwt_presentation(presentation)
        assert validation_result["valid"] is True
        assert len(validation_result["disclosures"]) == 0

    def test_minimal_sd_cwt_structure(self) -> None:
        """Test minimal valid SD-CWT with only required claims."""
        issuer_key = cose_key_generate()
        issuer_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_dict[-4])

        # Absolutely minimal EDN - empty object
        # cnf will be added automatically
        edn_claims = "{}"

        result = create_sd_cwt_with_holder_binding(edn_claims, issuer_signer)

        # Should still be valid
        assert "sd_cwt" in result
        assert len(result["disclosures"]) == 0

        # Decode and verify structure
        sd_cwt = result["sd_cwt"]
        decoded = cbor_utils.decode(sd_cwt)
        assert cbor_utils.is_tag(decoded)
        assert cbor_utils.get_tag_number(decoded) == 18  # COSE_Sign1

        payload = cbor_utils.decode(cbor_utils.get_tag_value(decoded)[2])

        # Only cnf claim should be present
        assert validate_sd_cwt_cnf(payload)
        # Count claims - should be minimal (just cnf)
        assert len([k for k in payload.keys() if not cbor_utils.is_simple_value(k)]) >= 1


class TestMalformedStructureValidation:
    """Test validation of malformed SD-CWT structures."""

    def test_invalid_sd_kbt_structures(self) -> None:
        """Test validation rejects malformed SD-KBT structures."""
        # Invalid CBOR
        result = validate_sd_cwt_presentation(b"invalid_cbor")
        assert result["valid"] is False
        assert "Invalid SD-KBT structure" in result["errors"]

        # Valid CBOR but not COSE_Sign1 tagged
        invalid_structure = cbor_utils.encode({"not": "cose_sign1"})
        result = validate_sd_cwt_presentation(invalid_structure)
        assert result["valid"] is False

        # COSE_Sign1 but wrong tag
        wrong_tag = cbor_utils.encode(cbor_utils.create_tag(17, [b"", {}, b"", b""]))  # Tag 17 instead of 18
        result = validate_sd_cwt_presentation(wrong_tag)
        assert result["valid"] is False

        # COSE_Sign1 with wrong array length
        wrong_length = cbor_utils.encode(cbor_utils.create_tag(18, [b"", {}, b""]))  # Missing signature
        result = validate_sd_cwt_presentation(wrong_length)
        assert result["valid"] is False

    def test_missing_required_headers(self) -> None:
        """Test SD-KBT validation when required headers are missing."""
        issuer_key = cose_key_generate()
        issuer_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_dict[-4])

        result = create_sd_cwt_with_holder_binding('{"test": "value"}', issuer_signer)
        holder_dict = cose_key_to_dict(result["holder_key"])
        holder_signer = ES256Signer(holder_dict[-4])

        # Create a valid presentation first
        valid_presentation = create_sd_cwt_presentation(
            result["sd_cwt"],
            result["disclosures"],
            [],
            holder_signer,
            "https://verifier.example",
            int(time.time())
        )

        # Decode and modify to remove required headers
        decoded = cbor_utils.decode(valid_presentation)
        cose_array = cbor_utils.get_tag_value(decoded)

        # Remove typ header by creating invalid protected header
        invalid_protected = cbor_utils.encode({1: -7})  # Only algorithm, no typ
        cose_array[0] = invalid_protected

        invalid_presentation = cbor_utils.encode(cbor_utils.create_tag(18, cose_array))

        # Should fail validation
        result = validate_sd_cwt_presentation(invalid_presentation)
        assert result["valid"] is False


class TestStandardClaimsHandling:
    """Test proper handling of standard CWT claims and cnonce."""

    def test_cnonce_in_sd_cwt_and_sd_kbt(self) -> None:
        """Test cnonce handling in both SD-CWT and SD-KBT."""
        issuer_key = cose_key_generate()
        issuer_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_dict[-4])

        # EDN with cnonce in SD-CWT
        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123",
            39: h'696e69745f636e6f6e6365',
            "data": 59("secret")
        }
        """

        result = create_sd_cwt_with_holder_binding(edn_claims, issuer_signer)
        holder_dict = cose_key_to_dict(result["holder_key"])
        holder_signer = ES256Signer(holder_dict[-4])

        # Create presentation with different cnonce
        presentation_cnonce = b"presentation_cnonce_2024"
        presentation = create_sd_cwt_presentation(
            result["sd_cwt"],
            result["disclosures"],
            [0],  # Select first disclosure
            holder_signer,
            "https://verifier.example",
            int(time.time()),
            cnonce=presentation_cnonce
        )

        # Validate
        validation_result = validate_sd_cwt_presentation(presentation)
        assert validation_result["valid"] is True
        assert validation_result["cnonce"] == presentation_cnonce

        # Verify original SD-CWT still has its cnonce
        sd_cwt = validation_result["sd_cwt"]
        decoded_sd_cwt = cbor_utils.decode(sd_cwt)
        sd_cwt_payload = cbor_utils.decode(cbor_utils.get_tag_value(decoded_sd_cwt)[2])
        assert 39 in sd_cwt_payload  # Original cnonce should be preserved

    def test_all_standard_cwt_claims(self) -> None:
        """Test SD-CWT with all standard CWT claims."""
        issuer_key = cose_key_generate()
        issuer_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_dict[-4])

        # EDN with all standard CWT claims
        edn_claims = """
        {
            1: "https://issuer.example",
            2: "subject123",
            3: "https://verifier.example",
            4: 1756656000,
            5: 1725243840,
            6: 1725244200,
            7: h'0123456789abcdef0123456789abcdef',
            39: h'636e6f6e636531323334353637383930',

            "custom1": 59("redacted1"),
            "custom2": "public2",
            "custom3": 59("redacted3")
        }
        """

        result = create_sd_cwt_with_holder_binding(edn_claims, issuer_signer)

        # Verify structure
        sd_cwt = result["sd_cwt"]
        decoded = cbor_utils.decode(sd_cwt)
        payload = cbor_utils.decode(cbor_utils.get_tag_value(decoded)[2])

        # All standard claims should be present
        standard_claims = [1, 2, 3, 4, 5, 6, 7, 39]
        for claim in standard_claims:
            assert claim in payload, f"Standard claim {claim} should be present"

        # cnf should be added
        assert 8 in payload

        # Custom public claim should be present
        assert payload["custom2"] == "public2"

        # Redacted claims should be absent
        assert "custom1" not in payload
        assert "custom3" not in payload

        # Should have 2 disclosures
        assert len(result["disclosures"]) == 2

        # Simple value 59 should have 2 hashes
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in payload
        assert len(payload[simple_59]) == 2

    def test_aud_claim_binding_validation(self) -> None:
        """Test that audience claims are properly validated."""
        issuer_key = cose_key_generate()
        issuer_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_dict[-4])

        # SD-CWT with audience claim
        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123",
            3: "https://intended-verifier.example",
            "data": 59("secret")
        }
        """

        result = create_sd_cwt_with_holder_binding(edn_claims, issuer_signer)
        holder_dict = cose_key_to_dict(result["holder_key"])
        holder_signer = ES256Signer(holder_dict[-4])

        # Create presentation for SAME verifier as in SD-CWT
        presentation = create_sd_cwt_presentation(
            result["sd_cwt"],
            result["disclosures"],
            [],
            holder_signer,
            "https://intended-verifier.example",  # Same as in SD-CWT
            int(time.time())
        )

        # Should be valid
        validation_result = validate_sd_cwt_presentation(presentation)
        assert validation_result["valid"] is True

        # Create presentation for DIFFERENT verifier
        presentation_different = create_sd_cwt_presentation(
            result["sd_cwt"],
            result["disclosures"],
            [],
            holder_signer,
            "https://different-verifier.example",  # Different verifier
            int(time.time())
        )

        # Should still be valid (SD-CWT and SD-KBT can have different audiences per spec)
        validation_result_different = validate_sd_cwt_presentation(presentation_different)
        assert validation_result_different["valid"] is True
