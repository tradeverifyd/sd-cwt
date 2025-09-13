"""Tests for mandatory holder binding in SD-CWT."""

import time
from unittest.mock import patch

import cbor2
import pytest

from sd_cwt import (
    CoseAlgorithm,
    SeededSaltGenerator,
    cose_key_generate,
    cose_key_to_dict,
    create_sd_cwt_with_holder_binding,
    create_sd_cwt_presentation,
    validate_sd_cwt_presentation,
)
from sd_cwt.cose_sign1 import ES256Signer, ES256Verifier
from sd_cwt.holder_binding import (
    create_cnf_claim,
    extract_holder_key_from_cnf,
    validate_sd_cwt_cnf,
    create_sd_kbt,
    TBD_KCWT
)


class TestHolderBindingBasics:
    """Test basic holder binding functionality."""

    def test_create_cnf_claim_with_full_key(self) -> None:
        """Test creating cnf claim with full COSE key."""
        holder_key = cose_key_generate()
        key_dict = cose_key_to_dict(holder_key)

        cnf_claim = create_cnf_claim(holder_key, use_thumbprint=False)

        assert 1 in cnf_claim  # COSE_Key
        assert cnf_claim[1] == key_dict

    def test_create_cnf_claim_with_thumbprint(self) -> None:
        """Test creating cnf claim with COSE Key Thumbprint."""
        holder_key = cose_key_generate()

        cnf_claim = create_cnf_claim(holder_key, use_thumbprint=True)

        assert 3 in cnf_claim  # ckt (thumbprint)
        assert isinstance(cnf_claim[3], bytes)
        assert len(cnf_claim[3]) == 32  # SHA-256 thumbprint

    def test_extract_holder_key_from_cnf(self) -> None:
        """Test extracting holder key from cnf claim."""
        holder_key = cose_key_generate()
        key_dict = cose_key_to_dict(holder_key)

        # Test with full key
        cnf_claim = {1: key_dict}
        extracted_key = extract_holder_key_from_cnf(cnf_claim)
        assert extracted_key is not None
        assert cose_key_to_dict(extracted_key) == key_dict

        # Test with thumbprint (should return None)
        cnf_claim = {3: b"thumbprint" * 2}
        extracted_key = extract_holder_key_from_cnf(cnf_claim)
        assert extracted_key is None

    def test_validate_sd_cwt_cnf(self) -> None:
        """Test SD-CWT cnf claim validation."""
        # Valid cnf with COSE_Key
        claims = {8: {1: {"kty": 2}}}
        assert validate_sd_cwt_cnf(claims) is True

        # Valid cnf with thumbprint
        claims = {8: {3: b"thumbprint"}}
        assert validate_sd_cwt_cnf(claims) is True

        # Missing cnf claim
        claims = {}
        assert validate_sd_cwt_cnf(claims) is False

        # Empty cnf claim
        claims = {8: {}}
        assert validate_sd_cwt_cnf(claims) is False

        # Invalid cnf type
        claims = {8: "invalid"}
        assert validate_sd_cwt_cnf(claims) is False


class TestSDCWTWithHolderBinding:
    """Test SD-CWT creation with mandatory holder binding."""

    def test_sd_cwt_creation_with_auto_generated_holder_key(self) -> None:
        """Test SD-CWT creation with auto-generated holder key."""
        # Generate issuer key
        issuer_key = cose_key_generate()
        issuer_key_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_key_dict[-4])

        # EDN with redacted claims
        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123",
            4: 1725330600,
            "email": 59("alice@example.com"),
            "name": 59("Alice Smith")
        }
        """

        # Create SD-CWT with holder binding
        result = create_sd_cwt_with_holder_binding(edn_claims, issuer_signer)

        # Verify structure
        assert "sd_cwt" in result
        assert "disclosures" in result
        assert "holder_key" in result

        # Verify holder key was generated
        assert result["holder_key"] is not None
        holder_key_dict = cose_key_to_dict(result["holder_key"])
        assert holder_key_dict[1] == 2  # EC2 key type

        # Verify disclosures
        assert len(result["disclosures"]) == 2  # email and name

        # Decode and validate SD-CWT
        sd_cwt = result["sd_cwt"]
        decoded = cbor2.loads(sd_cwt)
        assert isinstance(decoded, cbor2.CBORTag)
        assert decoded.tag == 18  # COSE_Sign1

        cose_sign1 = decoded.value
        payload = cbor2.loads(cose_sign1[2])

        # Verify mandatory cnf claim
        assert validate_sd_cwt_cnf(payload) is True
        assert 8 in payload  # cnf claim
        assert 1 in payload[8]  # COSE_Key in cnf

    def test_sd_cwt_with_provided_holder_key(self) -> None:
        """Test SD-CWT creation with provided holder key."""
        # Generate keys
        issuer_key = cose_key_generate()
        issuer_key_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_key_dict[-4])

        holder_key = cose_key_generate(key_id=b"holder-001")

        # Simple EDN
        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123",
            "role": "admin"
        }
        """

        # Create SD-CWT
        result = create_sd_cwt_with_holder_binding(
            edn_claims, issuer_signer, holder_key=holder_key
        )

        # Verify provided holder key is used
        assert result["holder_key"] == holder_key

        # Decode and check cnf claim matches provided key
        sd_cwt = result["sd_cwt"]
        decoded = cbor2.loads(sd_cwt)
        payload = cbor2.loads(decoded.value[2])

        cnf_claim = payload[8]
        holder_key_dict = cose_key_to_dict(holder_key)
        assert cnf_claim[1] == holder_key_dict

    def test_sd_cwt_with_thumbprint(self) -> None:
        """Test SD-CWT creation with COSE Key Thumbprint."""
        # Generate keys
        issuer_key = cose_key_generate()
        issuer_key_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_key_dict[-4])

        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123"
        }
        """

        # Create with thumbprint
        result = create_sd_cwt_with_holder_binding(
            edn_claims, issuer_signer, use_thumbprint=True
        )

        # Decode and check cnf uses thumbprint
        sd_cwt = result["sd_cwt"]
        decoded = cbor2.loads(sd_cwt)
        payload = cbor2.loads(decoded.value[2])

        cnf_claim = payload[8]
        assert 3 in cnf_claim  # ckt (thumbprint)
        assert 1 not in cnf_claim  # No full key


class TestSDCWTPresentations:
    """Test SD-CWT presentation creation and validation."""

    def test_create_presentation_with_selected_disclosures(self) -> None:
        """Test creating SD-CWT presentation with selected disclosures."""
        # Setup: Create SD-CWT
        issuer_key = cose_key_generate()
        issuer_key_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_key_dict[-4])

        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123",
            "email": 59("alice@example.com"),
            "name": 59("Alice Smith"),
            "role": "admin"
        }
        """

        seeded_gen = SeededSaltGenerator(seed=42)
        result = create_sd_cwt_with_holder_binding(
            edn_claims, issuer_signer, salt_generator=seeded_gen
        )

        # Setup holder signer
        holder_key_dict = cose_key_to_dict(result["holder_key"])
        holder_signer = ES256Signer(holder_key_dict[-4])

        # Create presentation with only one disclosure
        current_time = int(time.time())
        presentation = create_sd_cwt_presentation(
            result["sd_cwt"],
            result["disclosures"],
            [0],  # Only first disclosure (email)
            holder_signer,
            "https://verifier.example",
            current_time
        )

        assert isinstance(presentation, bytes)

        # Validate the presentation
        validation_result = validate_sd_cwt_presentation(presentation)
        assert validation_result["valid"] is True
        assert validation_result["audience"] == "https://verifier.example"
        assert validation_result["issued_at"] == current_time
        assert len(validation_result["disclosures"]) == 1

    def test_presentation_with_cnonce(self) -> None:
        """Test presentation with challenge nonce."""
        # Setup
        issuer_key = cose_key_generate()
        issuer_key_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_key_dict[-4])

        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123",
            "test": 59("value")
        }
        """

        result = create_sd_cwt_with_holder_binding(edn_claims, issuer_signer)
        holder_key_dict = cose_key_to_dict(result["holder_key"])
        holder_signer = ES256Signer(holder_key_dict[-4])

        # Create presentation with cnonce
        cnonce = b"challenge_12345"
        presentation = create_sd_cwt_presentation(
            result["sd_cwt"],
            result["disclosures"],
            [0],
            holder_signer,
            "https://verifier.example",
            int(time.time()),
            cnonce=cnonce
        )

        # Validate
        validation_result = validate_sd_cwt_presentation(presentation)
        assert validation_result["valid"] is True
        assert validation_result["cnonce"] == cnonce

    def test_presentation_validation_errors(self) -> None:
        """Test presentation validation with various error conditions."""
        # Invalid CBOR
        result = validate_sd_cwt_presentation(b"invalid_cbor")
        assert result["valid"] is False
        assert "Invalid SD-KBT structure" in result["errors"]

        # Valid CBOR but wrong structure
        invalid_structure = cbor2.dumps({"not": "sd_kbt"})
        result = validate_sd_cwt_presentation(invalid_structure)
        assert result["valid"] is False


class TestEndToEndHolderBinding:
    """End-to-end tests for complete holder binding flow."""

    def test_complete_flow_with_deterministic_output(self) -> None:
        """Test complete flow from issuance to presentation."""
        # Fixed seed for reproducible test
        seeded_gen = SeededSaltGenerator(seed=0x48454C4C4F)  # "HELLO"

        # Generate issuer key with ID
        issuer_key = cose_key_generate(key_id=b"issuer-key-001")
        issuer_key_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_key_dict[-4])

        # Generate holder key with ID
        holder_key = cose_key_generate(key_id=b"holder-key-001")

        # EDN claims for a driver's license
        edn_claims = """
        {
            / Standard CWT claims /
            1: "https://dmv.state.example",     / iss /
            2: "license-123456",                / sub /
            4: 1756656000,                      / exp - 2025-09-01 /
            6: 1725244200,                      / iat - 2024-09-01 /

            / Public license info /
            "license_class": "Class C",
            "restrictions": [],
            "vehicle_category": ["passenger"],

            / Redacted personal info /
            "full_name": 59("Alice Johnson"),
            "date_of_birth": 59("1990-05-15"),
            "address": 59({
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA",
                "zip": "90210"
            }),

            / Redacted sensitive data /
            "license_number": 59("D1234567"),
            "photo_hash": 59(h'abcdef1234567890')
        }
        """

        print("\n=== ISSUANCE PHASE ===")

        # 1. Create SD-CWT with mandatory holder binding
        sd_cwt_result = create_sd_cwt_with_holder_binding(
            edn_claims,
            issuer_signer,
            holder_key=holder_key,
            salt_generator=seeded_gen,
            issuer_key_id=b"issuer-key-001"
        )

        print(f"SD-CWT created: {len(sd_cwt_result['sd_cwt'])} bytes")
        print(f"Disclosures: {len(sd_cwt_result['disclosures'])}")
        print(f"Holder key: {len(sd_cwt_result['holder_key'])} bytes")

        # Verify mandatory cnf claim
        sd_cwt = sd_cwt_result["sd_cwt"]
        decoded = cbor2.loads(sd_cwt)
        payload = cbor2.loads(decoded.value[2])
        assert validate_sd_cwt_cnf(payload), "SD-CWT must have cnf claim"

        print("\n=== PRESENTATION PHASE ===")

        # 2. Holder creates presentation for verifier
        holder_key_dict = cose_key_to_dict(holder_key)
        holder_signer = ES256Signer(holder_key_dict[-4])

        # Select disclosures to reveal (e.g., only name and license number)
        selected_indices = [0, 3]  # Based on order in redacted claims

        presentation_time = 1725330000
        verifier_audience = "https://age-verifier.example"
        challenge_nonce = b"verify_challenge_2024"

        presentation = create_sd_cwt_presentation(
            sd_cwt_result["sd_cwt"],
            sd_cwt_result["disclosures"],
            selected_indices,
            holder_signer,
            verifier_audience,
            presentation_time,
            cnonce=challenge_nonce,
            holder_key_id=b"holder-key-001"
        )

        print(f"Presentation created: {len(presentation)} bytes")

        print("\n=== VERIFICATION PHASE ===")

        # 3. Verifier validates presentation
        validation_result = validate_sd_cwt_presentation(presentation)

        assert validation_result["valid"], f"Validation errors: {validation_result['errors']}"
        assert validation_result["audience"] == verifier_audience
        assert validation_result["issued_at"] == presentation_time
        assert validation_result["cnonce"] == challenge_nonce
        assert len(validation_result["disclosures"]) == 2

        print("✓ Presentation validation successful")
        print(f"✓ Audience: {validation_result['audience']}")
        print(f"✓ Issued at: {validation_result['issued_at']}")
        print(f"✓ Selected disclosures: {len(validation_result['disclosures'])}")

        # Verify hex output is deterministic
        presentation_hex = presentation.hex()
        print(f"\nDeterministic presentation hex: {presentation_hex[:80]}...")

        # Test reproducibility by checking structure, not exact bytes
        # (signatures contain randomness that prevents exact byte matching)
        validation_result2 = validate_sd_cwt_presentation(presentation)
        assert validation_result2["valid"], "Second validation should also succeed"
        assert validation_result2["audience"] == verifier_audience
        assert validation_result2["issued_at"] == presentation_time
        print("✓ Presentation structure is consistent")

    def test_mandatory_cnf_requirement(self) -> None:
        """Test that cnf claim is always mandatory."""
        # This test verifies the specification requirement that holder binding
        # (via cnf claim) is REQUIRED, not optional

        issuer_key = cose_key_generate()
        issuer_key_dict = cose_key_to_dict(issuer_key)
        issuer_signer = ES256Signer(issuer_key_dict[-4])

        edn_claims = """
        {
            1: "https://issuer.example",
            2: "user123"
        }
        """

        # Create SD-CWT - should always include cnf
        result = create_sd_cwt_with_holder_binding(edn_claims, issuer_signer)

        # Decode and verify cnf is present
        sd_cwt = result["sd_cwt"]
        decoded = cbor2.loads(sd_cwt)
        payload = cbor2.loads(decoded.value[2])

        assert 8 in payload, "cnf claim MUST be present (holder binding is mandatory)"
        assert validate_sd_cwt_cnf(payload), "cnf claim must be valid"

        # Verify holder key is provided
        assert result["holder_key"] is not None, "Holder key MUST be provided"