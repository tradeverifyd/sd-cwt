"""Unit tests for KBT (Key Binding Token) without redaction."""

import pytest
import time
from typing import Any, Dict

from sd_cwt import cbor_utils
from sd_cwt.cose_keys import cose_key_generate, CoseAlgorithm
from sd_cwt.cose_sign1 import ES256Signer, ES256Verifier, cose_sign1_sign, cose_sign1_verify
from sd_cwt.holder_binding import create_sd_kbt, create_cnf_claim, validate_sd_kbt_structure


class TestKeyBindingToken:
    """Test KBT functionality without redaction - key generation, sign, and present."""

    def test_generate_holder_key_for_kbt(self):
        """Test generating a holder key for Key Binding Token."""
        # Generate ES256 holder key
        holder_key_cbor = cose_key_generate(CoseAlgorithm.ES256)
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
        # Generate issuer and holder keys
        issuer_key_cbor = cose_key_generate(CoseAlgorithm.ES256)
        holder_key_cbor = cose_key_generate(CoseAlgorithm.ES256)

        # Create issuer signer
        issuer_key_dict = cbor_utils.decode(issuer_key_cbor)
        issuer_signer = ES256Signer(issuer_key_dict[-4])

        # Create basic claims with holder confirmation (no redaction)
        current_time = int(time.time())
        cnf_claim = create_cnf_claim(holder_key_cbor, use_thumbprint=False)

        basic_claims = {
            1: "https://issuer.example",      # iss
            2: "user@example.com",            # sub
            3: "https://verifier.example",    # aud
            6: current_time,                  # iat
            4: current_time + 3600,           # exp (1 hour)
            8: cnf_claim                      # cnf - holder key confirmation
        }

        # Sign SD-CWT (no selective disclosure, just basic CWT with cnf)
        protected_header = {
            1: -7,  # ES256
            16: "application/sd-cwt"  # typ
        }

        payload_cbor = cbor_utils.encode(basic_claims)
        sd_cwt = cose_sign1_sign(
            payload_cbor,
            issuer_signer,
            protected_header=protected_header
        )

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
        assert decoded_payload[8] == cnf_claim  # cnf claim present
        assert 59 not in decoded_payload, "No redaction - simple(59) should not be present"

        return sd_cwt, holder_key_cbor

    def test_create_key_binding_token(self):
        """Test creating a KBT to bind the holder key to a presentation."""
        # Create a simple SD-CWT first
        sd_cwt, holder_key_cbor = self.test_create_simple_sd_cwt_without_redaction()

        # Create holder signer from private key
        holder_key_dict = cbor_utils.decode(holder_key_cbor)
        holder_signer = ES256Signer(holder_key_dict[-4])

        # Create KBT parameters
        verifier_audience = "https://verifier.example/api"
        issued_at = int(time.time())
        cnonce = b"client-nonce-12345"  # Optional client nonce

        # Create SD-KBT
        sd_kbt = create_sd_kbt(
            sd_cwt_with_disclosures=sd_cwt,  # No disclosures in this simple case
            holder_signer=holder_signer,
            audience=verifier_audience,
            issued_at=issued_at,
            cnonce=cnonce
        )

        # Verify SD-KBT structure
        assert isinstance(sd_kbt, bytes)
        decoded_kbt = cbor_utils.decode(sd_kbt)
        assert cbor_utils.is_tag(decoded_kbt)
        assert cbor_utils.get_tag_number(decoded_kbt) == 18  # COSE_Sign1 tag

        # Decode KBT structure
        kbt_cose_sign1 = cbor_utils.get_tag_value(decoded_kbt)
        assert len(kbt_cose_sign1) == 4  # [protected, unprotected, payload, signature]

        # Verify protected header contains required fields
        protected_header_bytes = kbt_cose_sign1[0]
        protected_header = cbor_utils.decode(protected_header_bytes)

        assert protected_header[1] == -7, "Algorithm should be ES256"
        assert protected_header[16] == "application/kb+cwt", "Type should be kb+cwt"
        assert 13 in protected_header, "kcwt field (13) should be present in protected header"

        # Verify the kcwt field contains our SD-CWT
        kcwt_value = protected_header[13]
        assert kcwt_value == sd_cwt, "kcwt should contain the original SD-CWT"

        # Verify KBT payload contains required claims
        kbt_payload_bytes = kbt_cose_sign1[2]
        kbt_payload = cbor_utils.decode(kbt_payload_bytes)

        assert kbt_payload[3] == verifier_audience, "Audience should match verifier"
        assert kbt_payload[6] == issued_at, "Issued at time should match"
        assert kbt_payload[39] == cnonce, "Client nonce should be included"

        return sd_kbt, holder_key_cbor

    def test_validate_key_binding_token_structure(self):
        """Test validating KBT structure according to specification."""
        # Create a valid KBT
        sd_kbt, holder_key_cbor = self.test_create_key_binding_token()

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

        # Extract holder public key for verification
        holder_key_dict = cbor_utils.decode(holder_key_cbor)
        holder_verifier = ES256Verifier(holder_key_dict[-2], holder_key_dict[-3])

        # Verify KBT signature
        try:
            is_valid, payload_bytes = cose_sign1_verify(sd_kbt, holder_verifier)
            assert is_valid, "KBT signature should verify successfully"
            assert payload_bytes is not None, "Verified payload should not be None"

            # Decode the KBT payload
            kbt_payload = cbor_utils.decode(payload_bytes)
            assert kbt_payload[3] == "https://verifier.example/api", "Verified payload should contain audience"
            assert kbt_payload[6] is not None, "Verified payload should contain iat"

        except Exception as e:
            pytest.fail(f"KBT signature verification failed: {e}")

    def test_complete_kbt_workflow(self):
        """Test the complete KBT workflow: generate, sign, present, verify."""
        print("\\n=== Complete KBT Workflow Test ===")

        # Step 1: Generate holder key
        print("Step 1: Generating holder key...")
        holder_key_cbor = cose_key_generate(CoseAlgorithm.ES256)
        holder_key_dict = cbor_utils.decode(holder_key_cbor)
        print(f"✓ Generated ES256 holder key with curve P-{holder_key_dict[-1]}")

        # Step 2: Create SD-CWT with holder binding (no redaction)
        print("\\nStep 2: Creating SD-CWT with holder binding...")
        issuer_key_cbor = cose_key_generate(CoseAlgorithm.ES256)
        issuer_key_dict = cbor_utils.decode(issuer_key_cbor)
        issuer_signer = ES256Signer(issuer_key_dict[-4])

        cnf_claim = create_cnf_claim(holder_key_cbor, use_thumbprint=False)
        current_time = int(time.time())

        claims = {
            1: "https://issuer.example",
            2: "alice@example.com",
            3: "https://verifier.example",
            6: current_time,
            4: current_time + 3600,
            8: cnf_claim  # Holder key confirmation
        }

        protected_header = {1: -7, 16: "application/sd-cwt"}
        payload_cbor = cbor_utils.encode(claims)
        sd_cwt = cose_sign1_sign(payload_cbor, issuer_signer, protected_header=protected_header)
        print(f"✓ Created SD-CWT with holder confirmation (size: {len(sd_cwt)} bytes)")

        # Step 3: Create Key Binding Token (KBT)
        print("\\nStep 3: Creating Key Binding Token...")
        holder_signer = ES256Signer(holder_key_dict[-4])

        sd_kbt = create_sd_kbt(
            sd_cwt_with_disclosures=sd_cwt,
            holder_signer=holder_signer,
            audience="https://verifier.example/api",
            issued_at=int(time.time()),
            cnonce=b"unique-presentation-nonce"
        )
        print(f"✓ Created KBT for presentation (size: {len(sd_kbt)} bytes)")

        # Step 4: Validate KBT structure
        print("\\nStep 4: Validating KBT structure...")
        is_valid, extracted_info = validate_sd_kbt_structure(sd_kbt)
        assert is_valid, "KBT should have valid structure"
        print(f"✓ KBT structure valid - audience: {extracted_info['aud']}")
        print(f"✓ KBT contains SD-CWT of {len(extracted_info['kcwt'])} bytes")

        # Step 5: Verify KBT signature
        print("\\nStep 5: Verifying KBT signature...")
        holder_verifier = ES256Verifier(holder_key_dict[-2], holder_key_dict[-3])

        try:
            is_valid, payload_bytes = cose_sign1_verify(sd_kbt, holder_verifier)
            assert is_valid and payload_bytes is not None
            verified_payload = cbor_utils.decode(payload_bytes)
            print("✓ KBT signature verified successfully")
            print(f"✓ Presentation bound to audience: {verified_payload[3]}")
        except Exception as e:
            pytest.fail(f"KBT verification failed: {e}")

        print("\\n🎉 Complete KBT workflow successful!")

    def test_kbt_without_cnonce(self):
        """Test KBT creation without optional cnonce."""
        # Create basic SD-CWT
        sd_cwt, holder_key_cbor = self.test_create_simple_sd_cwt_without_redaction()

        # Create holder signer
        holder_key_dict = cbor_utils.decode(holder_key_cbor)
        holder_signer = ES256Signer(holder_key_dict[-4])

        # Create KBT without cnonce
        sd_kbt = create_sd_kbt(
            sd_cwt_with_disclosures=sd_cwt,
            holder_signer=holder_signer,
            audience="https://verifier.example",
            issued_at=int(time.time())
            # No cnonce parameter
        )

        # Verify KBT was created successfully
        is_valid, extracted_info = validate_sd_kbt_structure(sd_kbt)
        assert is_valid, "KBT without cnonce should be valid"
        assert extracted_info["cnonce"] is None, "cnonce should be None when not provided"

    def test_kbt_with_thumbprint_cnf(self):
        """Test KBT workflow with COSE Key Thumbprint in cnf claim."""
        # Generate keys
        issuer_key_cbor = cose_key_generate(CoseAlgorithm.ES256)
        holder_key_cbor = cose_key_generate(CoseAlgorithm.ES256)

        issuer_key_dict = cbor_utils.decode(issuer_key_cbor)
        holder_key_dict = cbor_utils.decode(holder_key_cbor)

        issuer_signer = ES256Signer(issuer_key_dict[-4])
        holder_signer = ES256Signer(holder_key_dict[-4])

        # Create SD-CWT with thumbprint-based cnf claim (smaller size)
        cnf_claim = create_cnf_claim(holder_key_cbor, use_thumbprint=True)
        assert 3 in cnf_claim, "Should use COSE Key Thumbprint (field 3)"
        assert isinstance(cnf_claim[3], bytes), "Thumbprint should be bytes"
        assert len(cnf_claim[3]) == 32, "SHA-256 thumbprint should be 32 bytes"

        claims = {
            1: "https://issuer.example",
            2: "user@example.com",
            6: int(time.time()),
            8: cnf_claim  # Thumbprint-based confirmation
        }

        protected_header = {1: -7, 16: "application/sd-cwt"}
        payload_cbor = cbor_utils.encode(claims)
        sd_cwt = cose_sign1_sign(payload_cbor, issuer_signer, protected_header=protected_header)

        # Create and verify KBT
        sd_kbt = create_sd_kbt(
            sd_cwt_with_disclosures=sd_cwt,
            holder_signer=holder_signer,
            audience="https://verifier.example",
            issued_at=int(time.time())
        )

        # Verify KBT structure
        is_valid, extracted_info = validate_sd_kbt_structure(sd_kbt)
        assert is_valid, "KBT with thumbprint cnf should be valid"

        # Verify KBT signature with holder key
        holder_verifier = ES256Verifier(holder_key_dict[-2], holder_key_dict[-3])
        is_valid, payload_bytes = cose_sign1_verify(sd_kbt, holder_verifier)
        assert is_valid and payload_bytes is not None, "KBT signature should verify"