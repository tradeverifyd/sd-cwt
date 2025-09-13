"""Unit tests for resolver functionality."""

import time

from sd_cwt import (
    CredentialSigner,
    CredentialVerifier,
    cbor_utils,
    cose_key_generate,
    cose_key_thumbprint_resolver,
)
from sd_cwt.cose_sign1 import cose_sign1_sign
from sd_cwt.holder_binding import create_cnf_claim
from sd_cwt.thumbprint import CoseKeyThumbprint


class TestResolvers:
    """Test resolver functionality for COSE keys."""

    def test_cose_key_thumbprint_resolver(self):
        """Test COSE key resolution by thumbprint."""
        # Generate test keys
        key1_cbor = cose_key_generate()
        key2_cbor = cose_key_generate()
        key3_cbor = cose_key_generate()

        # Decode keys and compute thumbprints
        key1 = cbor_utils.decode(key1_cbor)
        key2 = cbor_utils.decode(key2_cbor)
        key3 = cbor_utils.decode(key3_cbor)

        thumbprint1 = CoseKeyThumbprint.compute(key1, "sha256")
        thumbprint2 = CoseKeyThumbprint.compute(key2, "sha256")
        thumbprint3 = CoseKeyThumbprint.compute(key3, "sha256")

        # Create resolver with keys
        cose_keys = [key1_cbor, key2_cbor, key3_cbor]
        resolver = cose_key_thumbprint_resolver(cose_keys)

        # Test successful resolution
        resolved_key1 = resolver(thumbprint1)
        assert resolved_key1 == key1, "Should resolve correct key for thumbprint1"

        resolved_key2 = resolver(thumbprint2)
        assert resolved_key2 == key2, "Should resolve correct key for thumbprint2"

        resolved_key3 = resolver(thumbprint3)
        assert resolved_key3 == key3, "Should resolve correct key for thumbprint3"

        # Test unknown thumbprint - should raise ValueError
        unknown_thumbprint = b"x" * 32  # Invalid 32-byte thumbprint
        try:
            resolver(unknown_thumbprint)
            raise AssertionError("Should raise ValueError for unknown thumbprint")
        except ValueError as e:
            assert "Kid not found" in str(e)

    def test_cose_key_thumbprint_resolver_error_handling(self):
        """Test that resolver provides helpful error messages for missing thumbprints."""
        # Generate test keys
        key1_cbor = cose_key_generate()
        key2_cbor = cose_key_generate()

        # Create resolver
        resolver = cose_key_thumbprint_resolver([key1_cbor, key2_cbor])

        # Test with valid thumbprint
        key1 = cbor_utils.decode(key1_cbor)
        valid_thumbprint = CoseKeyThumbprint.compute(key1, "sha256")
        resolved_key = resolver(valid_thumbprint)
        assert resolved_key == key1

        # Test with invalid thumbprint - should get helpful error
        invalid_thumbprint = b"x" * 32
        try:
            resolver(invalid_thumbprint)
            raise AssertionError("Should raise ValueError for unknown thumbprint")
        except ValueError as e:
            error_msg = str(e)
            assert "Kid not found" in error_msg
            assert "Available kids" in error_msg
            assert "7878787878787878" in error_msg  # Part of invalid thumbprint (hex of 'xxxx...')

    def test_credential_verifier_with_thumbprint_resolver(self):
        """Test using cose_key_thumbprint_resolver to create CredentialVerifiers."""
        # Generate multiple issuer keys
        issuer1_key_cbor = cose_key_generate()
        issuer2_key_cbor = cose_key_generate()
        holder_key_cbor = cose_key_generate()

        issuer1_key = cbor_utils.decode(issuer1_key_cbor)
        issuer2_key = cbor_utils.decode(issuer2_key_cbor)

        # Create key resolver with multiple keys
        key_resolver = cose_key_thumbprint_resolver([issuer1_key_cbor, issuer2_key_cbor])

        # Compute thumbprints for resolution
        issuer1_thumbprint = CoseKeyThumbprint.compute(issuer1_key, "sha256")
        issuer2_thumbprint = CoseKeyThumbprint.compute(issuer2_key, "sha256")

        # Create CredentialVerifiers using the key resolver
        verifier1 = CredentialVerifier(key_resolver)
        verifier2 = CredentialVerifier(key_resolver)

        # Create SD-CWTs from both issuers
        signer1 = CredentialSigner(issuer1_key)
        signer2 = CredentialSigner(issuer2_key)

        cnf_claim = create_cnf_claim(holder_key_cbor, use_thumbprint=False)
        current_time = int(time.time())

        claims1 = {
            1: "https://issuer1.example",
            2: "user1@example.com",
            6: current_time,
            8: cnf_claim,
        }

        claims2 = {
            1: "https://issuer2.example",
            2: "user2@example.com",
            6: current_time,
            8: cnf_claim,
        }

        payload1_cbor = cbor_utils.encode(claims1)
        payload2_cbor = cbor_utils.encode(claims2)

        # Include thumbprints in protected headers so verifier can resolve keys
        protected_header1 = {1: -7, 4: issuer1_thumbprint}  # kid = thumbprint
        protected_header2 = {1: -7, 4: issuer2_thumbprint}  # kid = thumbprint

        sd_cwt1 = cose_sign1_sign(payload1_cbor, signer1, protected_header=protected_header1)
        sd_cwt2 = cose_sign1_sign(payload2_cbor, signer2, protected_header=protected_header2)

        # Test verification with correct verifiers (both use same resolver)
        is_valid1, payload1 = verifier1.verify(sd_cwt1)
        assert is_valid1, "Verifier1 should verify SD-CWT1"
        assert payload1[1] == "https://issuer1.example"

        is_valid2, payload2 = verifier2.verify(sd_cwt2)
        assert is_valid2, "Verifier2 should verify SD-CWT2"
        assert payload2[1] == "https://issuer2.example"


    def test_end_to_end_resolution_workflow(self):
        """Test complete resolution workflow from key pairs to SD-CWT verification."""
        # Step 1: Set up multiple issuer keys
        issuer1_key_cbor = cose_key_generate()
        issuer2_key_cbor = cose_key_generate()
        holder_key_cbor = cose_key_generate()

        issuer1_key = cbor_utils.decode(issuer1_key_cbor)
        issuer2_key = cbor_utils.decode(issuer2_key_cbor)

        issuer1_thumbprint = CoseKeyThumbprint.compute(issuer1_key, "sha256")
        issuer2_thumbprint = CoseKeyThumbprint.compute(issuer2_key, "sha256")

        # Step 2: Create key resolver
        key_resolver = cose_key_thumbprint_resolver([issuer1_key_cbor, issuer2_key_cbor])

        # Step 3: Create SD-CWTs from both issuers
        cnf_claim = create_cnf_claim(holder_key_cbor, use_thumbprint=False)
        current_time = int(time.time())

        # SD-CWT from issuer 1
        signer1 = CredentialSigner(issuer1_key)
        claims1 = {
            1: "https://issuer1.example",
            2: "user1@example.com",
            6: current_time,
            8: cnf_claim,
        }
        protected_header1 = {1: -7, 16: "application/sd-cwt", 4: issuer1_thumbprint}
        payload1_cbor = cbor_utils.encode(claims1)
        sd_cwt1 = cose_sign1_sign(payload1_cbor, signer1, protected_header=protected_header1)

        # SD-CWT from issuer 2
        signer2 = CredentialSigner(issuer2_key)
        claims2 = {
            1: "https://issuer2.example",
            2: "user2@example.com",
            6: current_time,
            8: cnf_claim,
        }
        protected_header2 = {1: -7, 16: "application/sd-cwt", 4: issuer2_thumbprint}
        payload2_cbor = cbor_utils.encode(claims2)
        sd_cwt2 = cose_sign1_sign(payload2_cbor, signer2, protected_header=protected_header2)

        # Step 4: Create verifier using key resolver and verify SD-CWTs
        verifier = CredentialVerifier(key_resolver)

        is_valid1, payload1 = verifier.verify(sd_cwt1)
        assert is_valid1, "SD-CWT 1 should verify successfully"
        assert payload1[1] == "https://issuer1.example"

        is_valid2, payload2 = verifier.verify(sd_cwt2)
        assert is_valid2, "SD-CWT 2 should verify successfully"
        assert payload2[1] == "https://issuer2.example"
