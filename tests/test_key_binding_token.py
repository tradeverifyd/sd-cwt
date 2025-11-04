"""Unit tests for KBT (Key Binding Token) without redaction."""

import time

from sd_cwt import (
    CredentialSigner,
    CredentialVerifier,
    PresentationSigner,
    PresentationVerifier,
    cbor_utils,
    cose_key_generate,
    cose_key_kid_resolver,
    get_presentation_verifier,
)
from sd_cwt.cose_sign1 import cose_sign1_sign
from sd_cwt.holder_binding import create_cnf_claim, create_sd_kbt, validate_sd_kbt_structure
from sd_cwt.thumbprint import CoseKeyThumbprint


class TestKeyBindingToken:
    """Test KBT functionality without redaction - key generation, sign, and present."""

    def test_generate_holder_key_for_kbt(self):
        """Test generating a holder key for Key Binding Token."""
        # Generate ES256 holder key
        holder_key_cbor = cose_key_generate()
        holder_key = cbor_utils.decode(holder_key_cbor)

        # Verify holder key structure for KBT use
        assert holder_key[1] == 2, "Key type should be EC2"
        assert holder_key[3] == -7, "Algorithm should be ES256"
        assert holder_key[-1] == 1, "Curve should be P-256"
        assert -4 in holder_key, "Private key component required for signing"

        # Verify key can be used for signing
        assert len(holder_key[-4]) == 32, "Private key should be 32 bytes for P-256"

    def test_create_simple_sd_cwt_without_redaction(self):
        """Test creating a simple SD-CWT with holder binding but no redaction."""
        sd_cwt_data = self._create_test_sd_cwt()
        sd_cwt, _, holder_key_cbor = sd_cwt_data

        # Verify SD-CWT structure
        assert isinstance(sd_cwt, bytes)
        decoded_sd_cwt = cbor_utils.decode(sd_cwt)
        assert cbor_utils.is_tag(decoded_sd_cwt)
        assert cbor_utils.get_tag_number(decoded_sd_cwt) == 18  # COSE_Sign1 tag

        # Verify we can decode the payload
        cose_sign1_value = cbor_utils.get_tag_value(decoded_sd_cwt)
        payload_bytes = cose_sign1_value[2]  # payload is third element
        decoded_payload = cbor_utils.decode(payload_bytes)

        assert decoded_payload[1] == "https://issuer.example"
        assert 8 in decoded_payload, "cnf claim should be present"
        assert 59 not in decoded_payload, "No redaction - simple(59) should not be present"

        return sd_cwt, holder_key_cbor

    def _create_test_sd_cwt(self):
        """Helper to create test SD-CWT with consistent structure."""
        # Generate issuer and holder keys
        issuer_key_cbor = cose_key_generate()
        holder_key_cbor = cose_key_generate()

        # Create issuer signer
        issuer_key_dict = cbor_utils.decode(issuer_key_cbor)
        issuer_signer = CredentialSigner(issuer_key_dict)

        # Create basic claims with holder confirmation (no redaction)
        current_time = int(time.time())
        cnf_claim = create_cnf_claim(holder_key_cbor, use_thumbprint=False)

        basic_claims = {
            1: "https://issuer.example",  # iss
            2: "user@example.com",  # sub
            3: "https://verifier.example",  # aud
            6: current_time,  # iat
            4: current_time + 3600,  # exp (1 hour)
            8: cnf_claim,  # cnf - holder key confirmation
        }

        # Compute thumbprint to use as kid
        issuer_thumbprint = CoseKeyThumbprint.compute(issuer_key_dict, "sha256")

        # Sign SD-CWT (no selective disclosure, just basic CWT with cnf)
        protected_header = {
            1: -7,  # ES256
            16: "application/sd-cwt",  # typ
            4: issuer_thumbprint,  # kid for key resolution
        }

        payload_cbor = cbor_utils.encode(basic_claims)
        sd_cwt = cose_sign1_sign(payload_cbor, issuer_signer, protected_header=protected_header)

        return sd_cwt, issuer_key_cbor, holder_key_cbor

    def test_verify_sd_cwt_signature(self):
        """Test verifying SD-CWT signature and extracting holder key."""
        sd_cwt_data = self._create_test_sd_cwt()
        sd_cwt, issuer_key_cbor, holder_key_cbor = sd_cwt_data

        # Create credential verifier with key resolver
        issuer_key_dict = cbor_utils.decode(issuer_key_cbor)
        issuer_thumbprint = CoseKeyThumbprint.compute(issuer_key_dict, "sha256")
        kid_key_pairs = [(issuer_thumbprint, issuer_key_cbor)]
        key_resolver = cose_key_kid_resolver(kid_key_pairs)
        credential_verifier = CredentialVerifier(key_resolver)

        # Verify SD-CWT signature
        is_valid, payload = credential_verifier.verify(sd_cwt)
        assert is_valid, "SD-CWT signature should verify"
        assert payload is not None, "Payload should not be None"

        # Extract holder key from cnf claim
        cnf_claim = payload[8]  # cnf claim
        assert 1 in cnf_claim, "cnf claim should contain full COSE key"
        extracted_holder_key = cnf_claim[1]

        # Verify extracted holder key matches original
        original_holder_key = cbor_utils.decode(holder_key_cbor)

        # Compare public components (private key won't be in SD-CWT)
        assert extracted_holder_key[1] == original_holder_key[1], "Key type should match"
        assert extracted_holder_key[3] == original_holder_key[3], "Algorithm should match"
        assert extracted_holder_key[-1] == original_holder_key[-1], "Curve should match"
        assert extracted_holder_key[-2] == original_holder_key[-2], "X coordinate should match"
        assert extracted_holder_key[-3] == original_holder_key[-3], "Y coordinate should match"

        return sd_cwt, extracted_holder_key, holder_key_cbor

    def test_create_key_binding_token(self):
        """Test creating a KBT to bind the holder key to a presentation."""
        sd_cwt_data = self._create_test_sd_cwt()
        sd_cwt, _, holder_key_cbor = sd_cwt_data

        # Create holder signer from private key
        holder_key_dict = cbor_utils.decode(holder_key_cbor)
        holder_signer = PresentationSigner(holder_key_dict)

        # Create KBT parameters
        verifier_audience = "https://verifier.example/api"
        issued_at = int(time.time())
        cnonce = b"client-nonce-12345"

        # Create SD-KBT
        holder_key_dict = cbor_utils.decode(holder_key_cbor)
        holder_thumbprint = CoseKeyThumbprint.compute(holder_key_dict, "sha256")
        sd_kbt = create_sd_kbt(
            sd_cwt_with_disclosures=sd_cwt,
            holder_signer=holder_signer,
            audience=verifier_audience,
            issued_at=issued_at,
            cnonce=cnonce,
            key_id=holder_thumbprint,
        )

        # Verify SD-KBT structure
        self._verify_kbt_structure(sd_kbt, sd_cwt, verifier_audience, issued_at, cnonce)

        return sd_kbt, holder_key_cbor

    def _verify_kbt_structure(
        self, sd_kbt, expected_sd_cwt, expected_audience, expected_iat, expected_cnonce
    ):
        """Helper to verify KBT structure."""
        assert isinstance(sd_kbt, bytes)
        decoded_kbt = cbor_utils.decode(sd_kbt)
        assert cbor_utils.is_tag(decoded_kbt)
        assert cbor_utils.get_tag_number(decoded_kbt) == 18

        # Decode KBT structure
        kbt_cose_sign1 = cbor_utils.get_tag_value(decoded_kbt)
        assert len(kbt_cose_sign1) == 4

        # Verify protected header
        protected_header = cbor_utils.decode(kbt_cose_sign1[0])
        assert protected_header[1] == -7, "Algorithm should be ES256"
        assert protected_header[16] == "application/kb+cwt", "Type should be kb+cwt"
        assert 13 in protected_header, "kcwt field should be present"
        assert protected_header[13] == expected_sd_cwt, "kcwt should contain the original SD-CWT"

        # Verify KBT payload
        kbt_payload = cbor_utils.decode(kbt_cose_sign1[2])
        assert kbt_payload[3] == expected_audience, "Audience should match"
        assert kbt_payload[6] == expected_iat, "Issued at should match"
        if expected_cnonce:
            assert kbt_payload[39] == expected_cnonce, "Client nonce should match"

    def test_validate_key_binding_token_structure(self):
        """Test validating KBT structure according to specification."""
        # Create a valid KBT
        sd_kbt, _ = self.test_create_key_binding_token()

        # Validate KBT structure
        is_valid, extracted_info = validate_sd_kbt_structure(sd_kbt)

        assert is_valid, "KBT should have valid structure"
        assert extracted_info is not None, "Should extract KBT information"

        # Verify extracted information
        assert extracted_info["aud"] == "https://verifier.example/api"
        assert isinstance(extracted_info["iat"], int)
        assert extracted_info["cnonce"] == b"client-nonce-12345"
        assert "kcwt" in extracted_info, "Should extract the SD-CWT from kcwt field"

        # Verify the extracted SD-CWT is valid CBOR
        extracted_sd_cwt = extracted_info["kcwt"]
        assert isinstance(extracted_sd_cwt, bytes)
        decoded_extracted = cbor_utils.decode(extracted_sd_cwt)
        assert cbor_utils.is_tag(decoded_extracted)

    def test_kbt_signature_verification(self):
        """Test that KBT signatures can be verified with holder public key."""
        # Create a valid KBT
        sd_kbt, holder_key_cbor = self.test_create_key_binding_token()

        # Create presentation verifier with holder key resolver
        holder_key_dict = cbor_utils.decode(holder_key_cbor)
        holder_thumbprint = CoseKeyThumbprint.compute(holder_key_dict, "sha256")
        kid_key_pairs = [(holder_thumbprint, holder_key_cbor)]
        holder_resolver = cose_key_kid_resolver(kid_key_pairs)
        presentation_verifier = PresentationVerifier(holder_resolver)

        # Verify KBT signature with audience validation
        expected_audience = "https://verifier.example/api"
        is_valid, kbt_payload = presentation_verifier.verify(sd_kbt, audience=expected_audience)
        assert is_valid, "KBT signature should verify successfully"
        assert kbt_payload is not None, "Verified payload should not be None"

        # Verify payload contents
        assert kbt_payload[3] == expected_audience, "Verified payload should contain audience"
        assert kbt_payload[6] is not None, "Verified payload should contain iat"

    def test_complete_kbt_workflow(self):
        """Test the complete KBT workflow: generate, sign, present, verify."""
        # Step 1: Generate holder key
        holder_key_cbor = cose_key_generate()
        holder_key_dict = cbor_utils.decode(holder_key_cbor)

        # Step 2: Create SD-CWT with holder binding (no redaction)
        issuer_key_cbor = cose_key_generate()
        issuer_key_dict = cbor_utils.decode(issuer_key_cbor)
        issuer_signer = CredentialSigner(issuer_key_dict)

        cnf_claim = create_cnf_claim(holder_key_cbor, use_thumbprint=False)
        current_time = int(time.time())

        claims = {
            1: "https://issuer.example",
            2: "alice@example.com",
            3: "https://verifier.example",
            6: current_time,
            4: current_time + 3600,
            8: cnf_claim,  # Holder key confirmation
        }

        # Compute thumbprint for key resolution
        issuer_thumbprint = CoseKeyThumbprint.compute(issuer_key_dict, "sha256")
        protected_header = {1: -7, 16: "application/sd-cwt", 4: issuer_thumbprint}
        payload_cbor = cbor_utils.encode(claims)
        sd_cwt = cose_sign1_sign(payload_cbor, issuer_signer, protected_header=protected_header)

        # Step 3: Create Key Binding Token (KBT)
        holder_signer = PresentationSigner(holder_key_dict)

        holder_thumbprint = CoseKeyThumbprint.compute(holder_key_dict, "sha256")
        sd_kbt = create_sd_kbt(
            sd_cwt_with_disclosures=sd_cwt,
            holder_signer=holder_signer,
            audience="https://verifier.example/api",
            issued_at=int(time.time()),
            cnonce=b"unique-presentation-nonce",
            key_id=holder_thumbprint,
        )

        # Step 4: Validate KBT structure
        is_valid, extracted_info = validate_sd_kbt_structure(sd_kbt)
        assert is_valid, "KBT should have valid structure"

        # Step 5: Verify KBT signature with audience validation
        expected_audience = "https://verifier.example/api"
        holder_thumbprint = CoseKeyThumbprint.compute(holder_key_dict, "sha256")
        kid_key_pairs = [(holder_thumbprint, holder_key_cbor)]
        holder_resolver = cose_key_kid_resolver(kid_key_pairs)
        presentation_verifier = PresentationVerifier(holder_resolver)
        is_valid, verified_payload = presentation_verifier.verify(
            sd_kbt, audience=expected_audience
        )
        assert is_valid and verified_payload is not None
        assert verified_payload[3] == expected_audience

    def test_kbt_without_cnonce(self):
        """Test KBT creation without optional cnonce."""
        # Create basic SD-CWT
        sd_cwt, holder_key_cbor = self.test_create_simple_sd_cwt_without_redaction()

        # Create holder signer
        holder_key_dict = cbor_utils.decode(holder_key_cbor)
        holder_signer = PresentationSigner(holder_key_dict)

        # Create KBT without cnonce
        holder_thumbprint = CoseKeyThumbprint.compute(holder_key_dict, "sha256")
        sd_kbt = create_sd_kbt(
            sd_cwt_with_disclosures=sd_cwt,
            holder_signer=holder_signer,
            audience="https://verifier.example",
            issued_at=int(time.time()),
            key_id=holder_thumbprint,
            # No cnonce parameter
        )

        # Verify KBT was created successfully
        is_valid, extracted_info = validate_sd_kbt_structure(sd_kbt)
        assert is_valid, "KBT without cnonce should be valid"
        assert extracted_info["cnonce"] is None, "cnonce should be None when not provided"

    def test_kbt_with_thumbprint_cnf(self):
        """Test KBT workflow with COSE Key Thumbprint in cnf claim."""
        # Generate keys
        issuer_key_cbor = cose_key_generate()
        holder_key_cbor = cose_key_generate()

        issuer_key_dict = cbor_utils.decode(issuer_key_cbor)
        holder_key_dict = cbor_utils.decode(holder_key_cbor)

        issuer_signer = CredentialSigner(issuer_key_dict)
        holder_signer = PresentationSigner(holder_key_dict)

        # Create SD-CWT with thumbprint-based cnf claim (smaller size)
        cnf_claim = create_cnf_claim(holder_key_cbor, use_thumbprint=True)
        assert 3 in cnf_claim, "Should use COSE Key Thumbprint (field 3)"
        assert isinstance(cnf_claim[3], bytes), "Thumbprint should be bytes"
        assert len(cnf_claim[3]) == 32, "SHA-256 thumbprint should be 32 bytes"

        claims = {
            1: "https://issuer.example",
            2: "user@example.com",
            6: int(time.time()),
            8: cnf_claim,  # Thumbprint-based confirmation
        }

        # Compute thumbprint for key resolution
        issuer_thumbprint = CoseKeyThumbprint.compute(issuer_key_dict, "sha256")
        protected_header = {1: -7, 16: "application/sd-cwt", 4: issuer_thumbprint}
        payload_cbor = cbor_utils.encode(claims)
        sd_cwt = cose_sign1_sign(payload_cbor, issuer_signer, protected_header=protected_header)

        # Create and verify KBT
        holder_thumbprint = CoseKeyThumbprint.compute(holder_key_dict, "sha256")
        sd_kbt = create_sd_kbt(
            sd_cwt_with_disclosures=sd_cwt,
            holder_signer=holder_signer,
            audience="https://verifier.example",
            issued_at=int(time.time()),
            key_id=holder_thumbprint,
        )

        # Verify KBT structure
        is_valid, extracted_info = validate_sd_kbt_structure(sd_kbt)
        assert is_valid, "KBT with thumbprint cnf should be valid"

        # Verify KBT signature with holder key and audience validation
        expected_audience = "https://verifier.example"
        holder_thumbprint = CoseKeyThumbprint.compute(holder_key_dict, "sha256")
        kid_key_pairs = [(holder_thumbprint, holder_key_cbor)]
        holder_resolver = cose_key_kid_resolver(kid_key_pairs)
        presentation_verifier = PresentationVerifier(holder_resolver)
        is_valid, payload = presentation_verifier.verify(sd_kbt, audience=expected_audience)
        assert is_valid and payload is not None, "KBT signature should verify"

    def test_complete_verification_chain(self):
        """Test the complete verification chain: SD-CWT → holder KBT → audience."""
        # Step 1: Create SD-CWT with holder binding
        sd_cwt_data = self._create_test_sd_cwt()
        sd_cwt, issuer_key_cbor, holder_key_cbor = sd_cwt_data

        # Step 2: Create credential verifier and verify SD-CWT
        issuer_key_dict = cbor_utils.decode(issuer_key_cbor)
        issuer_thumbprint = CoseKeyThumbprint.compute(issuer_key_dict, "sha256")
        kid_key_pairs = [(issuer_thumbprint, issuer_key_cbor)]
        issuer_resolver = cose_key_kid_resolver(kid_key_pairs)
        credential_verifier = CredentialVerifier(issuer_resolver)

        is_valid, payload = credential_verifier.verify(sd_cwt)
        assert is_valid, "SD-CWT signature should verify"
        assert payload is not None, "SD-CWT payload should not be None"

        # Step 3: Extract presentation verifier using utility function
        # For embedded keys, no holder_key_resolver needed
        presentation_verifier = get_presentation_verifier(sd_cwt, credential_verifier)
        assert presentation_verifier is not None, "Should extract presentation verifier"

        # Step 4: Create KBT using holder's private key
        holder_key_dict = cbor_utils.decode(holder_key_cbor)
        holder_signer = PresentationSigner(holder_key_dict)

        expected_audience = "https://verifier.example/presentation"
        holder_thumbprint = CoseKeyThumbprint.compute(holder_key_dict, "sha256")
        sd_kbt = create_sd_kbt(
            sd_cwt_with_disclosures=sd_cwt,
            holder_signer=holder_signer,
            audience=expected_audience,
            issued_at=int(time.time()),
            cnonce=b"verification-chain-nonce",
            key_id=holder_thumbprint,
        )

        # Step 5: Verify holder-signed KBT with audience validation
        is_valid, kbt_payload = presentation_verifier.verify(sd_kbt, audience=expected_audience)
        assert is_valid, "KBT signature should verify with correct audience"
        assert kbt_payload is not None, "KBT payload should not be None"

        # Step 6: Verify audience was correctly validated during verification
        actual_audience = kbt_payload[3]  # aud claim
        assert (
            actual_audience == expected_audience
        ), f"Audience should match: expected {expected_audience}, got {actual_audience}"

        # Additional verification: ensure KBT contains the original SD-CWT
        is_valid, _ = validate_sd_kbt_structure(sd_kbt)
        assert is_valid, "KBT structure should be valid"

    def test_presentation_verifier_audience_validation(self):
        """Test that PresentationVerifier validates audience correctly."""
        # Create SD-CWT and KBT
        sd_cwt_data = self._create_test_sd_cwt()
        sd_cwt, issuer_key_cbor, holder_key_cbor = sd_cwt_data

        # Create presentation verifier
        issuer_key_dict = cbor_utils.decode(issuer_key_cbor)
        issuer_thumbprint = CoseKeyThumbprint.compute(issuer_key_dict, "sha256")
        kid_key_pairs = [(issuer_thumbprint, issuer_key_cbor)]
        issuer_resolver = cose_key_kid_resolver(kid_key_pairs)
        credential_verifier = CredentialVerifier(issuer_resolver)

        # For embedded keys, no holder_key_resolver needed
        presentation_verifier = get_presentation_verifier(sd_cwt, credential_verifier)
        assert presentation_verifier is not None

        # Create KBT with specific audience
        holder_key_dict = cbor_utils.decode(holder_key_cbor)
        holder_signer = PresentationSigner(holder_key_dict)

        correct_audience = "https://verifier.example/correct"
        holder_thumbprint = CoseKeyThumbprint.compute(holder_key_dict, "sha256")
        sd_kbt = create_sd_kbt(
            sd_cwt_with_disclosures=sd_cwt,
            holder_signer=holder_signer,
            audience=correct_audience,
            issued_at=int(time.time()),
            cnonce=b"audience-test-nonce",
            key_id=holder_thumbprint,
        )

        # Test 1: Verification should succeed with correct audience
        is_valid, payload = presentation_verifier.verify(sd_kbt, audience=correct_audience)
        assert is_valid, "Verification should succeed with correct audience"
        assert payload is not None
        assert payload[3] == correct_audience

        # Test 2: Verification should fail with wrong audience
        wrong_audience = "https://verifier.example/wrong"
        is_valid, payload = presentation_verifier.verify(sd_kbt, audience=wrong_audience)
        assert not is_valid, "Verification should fail with wrong audience"
        assert payload is None

        # Test 3: Verification should succeed without audience parameter (no validation)
        is_valid, payload = presentation_verifier.verify(sd_kbt)
        assert is_valid, "Verification should succeed without audience validation"
        assert payload is not None
        assert payload[3] == correct_audience

    def test_ckt_based_kbt_verification(self):
        """Test KBT verification when SD-CWT uses COSE Key Thumbprint in cnf."""
        # Step 1: Generate keys
        issuer_key_cbor = cose_key_generate()
        holder_key_cbor = cose_key_generate()

        issuer_key_dict = cbor_utils.decode(issuer_key_cbor)
        holder_key_dict = cbor_utils.decode(holder_key_cbor)

        # Step 2: Create SD-CWT with thumbprint-based cnf claim
        current_time = int(time.time())
        holder_thumbprint = CoseKeyThumbprint.compute(holder_key_dict, "sha256")

        # cnf claim using thumbprint (key 3) instead of embedded key (key 1)
        cnf_claim = {3: holder_thumbprint}  # COSE Key Thumbprint

        claims = {
            1: "https://issuer.example",
            2: "user@example.com",
            6: current_time,
            8: cnf_claim,  # cnf with thumbprint reference
        }

        # Create credential verifier
        issuer_thumbprint = CoseKeyThumbprint.compute(issuer_key_dict, "sha256")
        issuer_kid_pairs = [(issuer_thumbprint, issuer_key_cbor)]
        issuer_resolver = cose_key_kid_resolver(issuer_kid_pairs)
        credential_verifier = CredentialVerifier(issuer_resolver)

        # Sign SD-CWT
        signer = CredentialSigner(issuer_key_dict)
        protected_header = {1: -7, 4: issuer_thumbprint}
        payload_cbor = cbor_utils.encode(claims)
        sd_cwt = cose_sign1_sign(payload_cbor, signer, protected_header=protected_header)

        # Step 3: Create holder key resolver (maps thumbprints to keys)
        holder_kid_pairs = [(holder_thumbprint, holder_key_cbor)]
        holder_resolver = cose_key_kid_resolver(holder_kid_pairs)

        # Step 4: Extract presentation verifier using ckt-based resolution
        presentation_verifier = get_presentation_verifier(
            sd_cwt, credential_verifier, holder_resolver
        )
        assert (
            presentation_verifier is not None
        ), "Should create presentation verifier for ckt-based cnf"

        # Step 5: Create KBT using holder's private key
        holder_signer = PresentationSigner(holder_key_dict)
        expected_audience = "https://verifier.example/ckt"

        # KBT should use holder key's thumbprint as kid
        kbt_kid = CoseKeyThumbprint.compute(holder_key_dict, "sha256")

        kbt = create_sd_kbt(
            sd_cwt_with_disclosures=sd_cwt,
            holder_signer=holder_signer,
            audience=expected_audience,
            issued_at=int(time.time()),
            key_id=kbt_kid,
        )

        # Step 6: Verify KBT signature
        is_valid, kbt_payload = presentation_verifier.verify(kbt, audience=expected_audience)
        assert is_valid, "KBT verification should succeed with ckt-based cnf"
        assert kbt_payload is not None, "KBT payload should not be None"
        assert kbt_payload[3] == expected_audience, "Audience should match"
