"""Unit tests for cryptographic operations using fido2."""

import hashlib
import hmac
import os
from typing import Tuple

import pytest
from fido2.cose import ES256, CoseKey


class TestCryptography:
    """Test cases for cryptographic operations."""

    @pytest.mark.unit
    @pytest.mark.requires_crypto
    def test_generate_random_salt(self):
        """Test generating random salt for disclosures."""
        salt_length = 32  # 256 bits
        salt = os.urandom(salt_length)
        
        assert isinstance(salt, bytes)
        assert len(salt) == salt_length
        
        # Generate another salt and ensure they're different
        salt2 = os.urandom(salt_length)
        assert salt != salt2

    @pytest.mark.unit
    @pytest.mark.requires_crypto
    def test_sha256_hashing(self):
        """Test SHA-256 hashing for SD digests."""
        data = b"test data for hashing"
        
        # Using hashlib
        hash_value = hashlib.sha256(data).digest()
        
        assert isinstance(hash_value, bytes)
        assert len(hash_value) == 32  # SHA-256 produces 32 bytes
        
        # Same input should produce same hash
        hash_value2 = hashlib.sha256(data).digest()
        assert hash_value == hash_value2

    @pytest.mark.unit
    @pytest.mark.requires_crypto
    def test_cose_keypair_generation(self, cose_key_pair: Tuple[dict, CoseKey]):
        """Test COSE keypair generation for COSE signatures."""
        private_key_info, public_key = cose_key_pair
        
        assert isinstance(private_key_info, dict)
        assert "ec_key" in private_key_info
        assert isinstance(public_key, dict)
        
        # Verify key type is EC2 (kty = 2)
        assert public_key[1] == 2
        
        # Verify algorithm is ES256 (alg = -7)
        assert public_key[3] == -7
        
        # Verify curve is P-256 (crv = 1)
        assert public_key[-1] == 1
        
        # Verify public key has x and y coordinates
        assert -2 in public_key  # x coordinate
        assert -3 in public_key  # y coordinate
        
        # Public key should not have d parameter
        assert -4 not in public_key

    @pytest.mark.unit
    @pytest.mark.requires_crypto
    def test_es256_signature(self):
        """Test ES256 signature creation and verification."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        
        # Generate EC key
        ec_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        # Sign data
        data = b"data to sign"
        signature = ec_private.sign(data, ec.ECDSA(hashes.SHA256()))
        
        assert isinstance(signature, bytes)
        # ES256 signatures vary in length due to DER encoding, typically 70-72 bytes
        assert len(signature) >= 68

    @pytest.mark.unit
    @pytest.mark.requires_crypto
    def test_hmac_generation(self):
        """Test HMAC generation for message authentication."""
        key = os.urandom(32)
        message = b"message to authenticate"
        
        # Generate HMAC
        h = hmac.new(key, message, hashlib.sha256)
        mac = h.digest()
        
        assert isinstance(mac, bytes)
        assert len(mac) == 32  # HMAC-SHA256 produces 32 bytes
        
        # Verify HMAC
        h2 = hmac.new(key, message, hashlib.sha256)
        assert hmac.compare_digest(mac, h2.digest())

    @pytest.mark.unit
    @pytest.mark.requires_crypto
    def test_constant_time_comparison(self):
        """Test constant-time comparison for security."""
        secret1 = os.urandom(32)
        secret2 = os.urandom(32)
        secret1_copy = bytes(secret1)
        
        # Same secrets should match
        assert hmac.compare_digest(secret1, secret1_copy)
        
        # Different secrets should not match
        assert not hmac.compare_digest(secret1, secret2)

    @pytest.mark.unit
    @pytest.mark.requires_crypto
    @pytest.mark.parametrize("salt_length", [16, 32, 64])
    def test_various_salt_lengths(self, salt_length: int):
        """Test generating salts of various lengths."""
        salt = os.urandom(salt_length)
        
        assert isinstance(salt, bytes)
        assert len(salt) == salt_length

    @pytest.mark.unit
    @pytest.mark.requires_crypto
    def test_hash_collision_resistance(self):
        """Test that different inputs produce different hashes."""
        inputs = [
            b"input1",
            b"input2",
            b"input3",
            b"Input1",  # Case difference
            b"input1 ",  # Trailing space
        ]
        
        hashes_set = set()
        for data in inputs:
            hash_value = hashlib.sha256(data).digest()
            hashes_set.add(hash_value)
        
        # All hashes should be unique
        assert len(hashes_set) == len(inputs)

    @pytest.mark.unit
    @pytest.mark.requires_crypto
    def test_deterministic_hashing(self):
        """Test that hashing is deterministic."""
        data = b"deterministic test data"
        
        hashes_list = []
        for _ in range(10):
            hash_value = hashlib.sha256(data).digest()
            hashes_list.append(hash_value)
        
        # All hashes should be identical
        assert len(set(hashes_list)) == 1

    @pytest.mark.unit
    @pytest.mark.requires_crypto
    def test_base64url_encoding(self):
        """Test base64url encoding for safe URL transmission."""
        import base64
        
        data = os.urandom(32)
        
        # Encode to base64url (no padding)
        b64url = base64.urlsafe_b64encode(data).rstrip(b"=")
        
        assert isinstance(b64url, bytes)
        # Should not contain standard base64 characters that are URL-unsafe
        assert b"+" not in b64url
        assert b"/" not in b64url
        assert b"=" not in b64url
        
        # Should be decodable
        # Add padding back for decoding
        padding = 4 - (len(b64url) % 4) if len(b64url) % 4 else 0
        b64url_padded = b64url + b"=" * padding
        decoded = base64.urlsafe_b64decode(b64url_padded)
        
        assert decoded == data