"""Unit tests for cryptographic operations."""

import hashlib
import hmac
import os
from typing import Tuple

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


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
    def test_ec_keypair_generation(
        self, ec_keypair: Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]
    ):
        """Test EC keypair generation for COSE signatures."""
        private_key, public_key = ec_keypair
        
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)
        
        # Verify curve is P-256 (SECP256R1)
        assert private_key.curve.name == "secp256r1"
        assert public_key.curve.name == "secp256r1"

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
    def test_key_derivation(self):
        """Test key derivation for additional keys."""
        # Using HKDF for key derivation
        salt = os.urandom(32)
        info = b"sd-cwt-key-derivation"
        key_material = os.urandom(32)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        )
        
        derived_key = hkdf.derive(key_material)
        
        assert isinstance(derived_key, bytes)
        assert len(derived_key) == 32

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