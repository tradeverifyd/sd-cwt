from sd_cwt import cbor_utils
"""Tests for EDN redaction and disclosure handling."""

import hashlib
from unittest.mock import patch

import pytest

from sd_cwt.redaction import (
    REDACTED_CLAIM_KEY_TAG,
    REDACTED_CLAIM_ELEMENT_TAG,
    SecureSaltGenerator,
    SeededSaltGenerator,
    build_sd_cwt_claims,
    cbor_to_dict,
    create_disclosure,
    edn_to_redacted_cbor,
    find_redacted_claims,
    generate_salt,
    hash_disclosure,
    parse_edn_to_cbor,
    process_redactions,
)


class TestBasicFunctions:
    """Test individual redaction functions."""

    def test_parse_edn_to_cbor(self) -> None:
        """Test EDN string parsing to CBOR."""
        edn = '{"name": "Alice", "age": 30}'
        cbor_bytes = parse_edn_to_cbor(edn)

        assert isinstance(cbor_bytes, bytes)

        # Decode and verify
        decoded = cbor_utils.decode(cbor_bytes)
        assert decoded["name"] == "Alice"
        assert decoded["age"] == 30

    def test_cbor_to_dict(self) -> None:
        """Test CBOR bytes to dictionary conversion."""
        data = {"test": "value", "number": 42}
        cbor_bytes = cbor_utils.encode(data)

        result = cbor_to_dict(cbor_bytes)

        assert result == data
        assert isinstance(result, dict)

    def test_generate_salt(self) -> None:
        """Test salt generation."""
        # Default length (16 bytes)
        salt1 = generate_salt()
        assert len(salt1) == 16
        assert isinstance(salt1, bytes)

        # Custom length
        salt2 = generate_salt(32)
        assert len(salt2) == 32

        # Salts should be different
        salt3 = generate_salt()
        assert salt1 != salt3

    def test_create_disclosure(self) -> None:
        """Test disclosure array creation."""
        salt = b"test_salt_16byte"
        claim_name = "email"
        claim_value = "alice@example.com"

        disclosure = create_disclosure(salt, claim_name, claim_value)

        assert isinstance(disclosure, bytes)

        # Decode and verify structure [salt, value, key]
        decoded = cbor_utils.decode(disclosure)
        assert isinstance(decoded, list)
        assert len(decoded) == 3
        assert decoded[0] == salt
        assert decoded[1] == claim_value
        assert decoded[2] == claim_name

    def test_hash_disclosure(self) -> None:
        """Test disclosure hashing."""
        disclosure = b"test_disclosure_data"

        # SHA-256 (default)
        hash256 = hash_disclosure(disclosure)
        assert len(hash256) == 32
        assert hash256 == hashlib.sha256(disclosure).digest()

        # SHA-384
        hash384 = hash_disclosure(disclosure, "sha-384")
        assert len(hash384) == 48
        assert hash384 == hashlib.sha384(disclosure).digest()

        # SHA-512
        hash512 = hash_disclosure(disclosure, "sha-512")
        assert len(hash512) == 64
        assert hash512 == hashlib.sha512(disclosure).digest()

        # Unsupported algorithm
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            hash_disclosure(disclosure, "md5")


class TestRedactionDetection:
    """Test redaction detection in claims."""

    def test_find_redacted_claims_simple(self) -> None:
        """Test finding simple redacted claims."""
        claims = {
            "name": "Alice",
            "email": cbor_utils.create_tag(REDACTED_CLAIM_KEY_TAG, "alice@example.com"),
            "age": 30,
        }

        redacted = find_redacted_claims(claims)

        assert len(redacted) == 1
        assert redacted[0] == ([], "email")

    def test_find_redacted_claims_nested(self) -> None:
        """Test finding nested redacted claims."""
        claims = {
            "name": "Alice",
            "address": {
                "street": "123 Main St",
                "city": cbor_utils.create_tag(REDACTED_CLAIM_KEY_TAG, "Seattle"),
                "zip": "98101",
            },
        }

        redacted = find_redacted_claims(claims)

        assert len(redacted) == 1
        assert redacted[0] == (["address"], "city")

    def test_find_redacted_claims_array(self) -> None:
        """Test finding redacted array elements."""
        claims = {
            "name": "Alice",
            "phones": [
                "555-0100",
                cbor_utils.create_tag(REDACTED_CLAIM_ELEMENT_TAG, "555-0101"),
                "555-0102",
            ],
        }

        redacted = find_redacted_claims(claims)

        assert len(redacted) == 1
        assert redacted[0] == (["phones", 1], "555-0101")

    def test_find_redacted_claims_multiple(self) -> None:
        """Test finding multiple redacted claims."""
        claims = {
            "name": cbor_utils.create_tag(REDACTED_CLAIM_KEY_TAG, "Alice"),
            "email": cbor_utils.create_tag(REDACTED_CLAIM_KEY_TAG, "alice@example.com"),
            "nested": {
                "field1": "value1",
                "field2": cbor_utils.create_tag(REDACTED_CLAIM_KEY_TAG, "value2"),
            },
        }

        redacted = find_redacted_claims(claims)

        assert len(redacted) == 3
        paths = [r[1] for r in redacted]
        assert "name" in paths
        assert "email" in paths
        assert "field2" in paths


class TestRedactionProcessing:
    """Test redaction processing and disclosure creation."""

    def test_process_redactions_simple(self) -> None:
        """Test processing simple redactions."""
        claims = {
            "name": "Alice",
            "email": cbor_utils.create_tag(REDACTED_CLAIM_KEY_TAG, "alice@example.com"),
            "age": 30,
        }

        redacted_paths = [([], "email")]

        with patch("sd_cwt.redaction.generate_salt", return_value=b"0" * 16):
            redacted_claims, disclosures, hashes = process_redactions(
                claims, redacted_paths
            )

        # Check redacted claims
        assert "name" in redacted_claims
        assert "age" in redacted_claims
        assert "email" not in redacted_claims

        # Check disclosures
        assert len(disclosures) == 1
        decoded_disclosure = cbor_utils.decode(disclosures[0])
        assert decoded_disclosure[0] == b"0" * 16  # Salt
        assert decoded_disclosure[1] == "alice@example.com"  # Value
        assert decoded_disclosure[2] == "email"  # Key

        # Check hashes
        assert len(hashes) == 1
        assert len(hashes[0]) == 32  # SHA-256 hash

    def test_build_sd_cwt_claims(self) -> None:
        """Test building SD-CWT claims with hashes."""
        claims = {"iss": "https://issuer.example", "sub": "user123"}
        hashes = [b"hash1_32bytes" + b"0" * 19, b"hash2_32bytes" + b"0" * 19]

        sd_cwt_claims = build_sd_cwt_claims(claims, hashes)

        # Check original claims are preserved
        assert sd_cwt_claims["iss"] == "https://issuer.example"
        assert sd_cwt_claims["sub"] == "user123"

        # Check simple value 59 is used for hashes
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in sd_cwt_claims
        assert sd_cwt_claims[simple_59] == hashes

    def test_build_sd_cwt_claims_no_hashes(self) -> None:
        """Test building SD-CWT claims without hashes."""
        claims = {"iss": "https://issuer.example"}
        hashes = []

        sd_cwt_claims = build_sd_cwt_claims(claims, hashes)

        assert sd_cwt_claims == claims
        assert cbor_utils.create_simple_value(59) not in sd_cwt_claims


class TestEndToEnd:
    """End-to-end tests for EDN to CBOR conversion."""

    def test_edn_to_redacted_cbor_simple(self) -> None:
        """Test simple EDN to redacted CBOR conversion."""
        edn = """
        {
            "iss": "https://issuer.example",
            "sub": "user123",
            "email": 59("alice@example.com"),
            "age": 30
        }
        """

        with patch("sd_cwt.redaction.generate_salt", return_value=b"0" * 16):
            cbor_claims, disclosures = edn_to_redacted_cbor(edn)

        # Decode CBOR claims
        claims = cbor_utils.decode(cbor_claims)

        # Check non-redacted claims
        assert claims["iss"] == "https://issuer.example"
        assert claims["sub"] == "user123"
        assert claims["age"] == 30

        # Check redacted claim is removed
        assert "email" not in claims

        # Check simple value 59 contains hashes
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in claims
        assert len(claims[simple_59]) == 1  # One hash

        # Check disclosures
        assert len(disclosures) == 1
        decoded = cbor_utils.decode(disclosures[0])
        assert decoded[2] == "email"
        assert decoded[1] == "alice@example.com"

    def test_edn_to_redacted_cbor_complex(self) -> None:
        """Test complex EDN with nested redactions to CBOR."""
        edn = """
        {
            1: "https://issuer.example",
            2: "https://device.example",
            4: 1725330600,
            500: 59(true),
            501: "ABCD-123456",
            502: 60([1549560720, 1612498440, 1674004740]),
            503: {
                "country": "us",
                "region": 59("ca"),
                "postal_code": "94188"
            }
        }
        """

        cbor_claims, disclosures = edn_to_redacted_cbor(edn)

        # Decode CBOR claims
        claims = cbor_utils.decode(cbor_claims)

        # Check non-redacted claims
        assert claims[1] == "https://issuer.example"
        assert claims[2] == "https://device.example"
        assert claims[4] == 1725330600
        assert claims[501] == "ABCD-123456"

        # Check nested non-redacted
        assert claims[503]["country"] == "us"
        assert claims[503]["postal_code"] == "94188"

        # Check redacted claims are removed
        assert 500 not in claims
        assert 502 not in claims
        assert "region" not in claims[503]

        # Check disclosures exist
        # Should have: 500 (redacted key), region (nested key), 502 (array element)
        assert len(disclosures) >= 2  # At least two redacted items

    def test_edn_to_cbor_hex_output(self) -> None:
        """Test EDN to CBOR with hex output for sharing."""
        edn = """
        {
            "iss": "https://issuer.example",
            "sub": "user123",
            "email": 59("alice@example.com"),
            "name": 59("Alice Smith")
        }
        """

        # Use fixed salt for reproducible output
        with patch("sd_cwt.redaction.generate_salt", return_value=b"\xaa" * 16):
            cbor_claims, disclosures = edn_to_redacted_cbor(edn)

        # Convert to hex for sharing
        cbor_hex = cbor_claims.hex()
        assert isinstance(cbor_hex, str)
        assert all(c in "0123456789abcdef" for c in cbor_hex)

        # Verify hex can be decoded back
        cbor_from_hex = bytes.fromhex(cbor_hex)
        claims = cbor_utils.decode(cbor_from_hex)

        assert claims["iss"] == "https://issuer.example"
        assert claims["sub"] == "user123"
        assert "email" not in claims
        assert "name" not in claims

        # Simple value 59 should contain 2 hashes
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in claims
        assert len(claims[simple_59]) == 2

        # Print hex for demonstration
        print(f"\nCBOR Claims (hex): {cbor_hex}")
        print(f"Number of disclosures: {len(disclosures)}")
        for i, disclosure in enumerate(disclosures):
            print(f"Disclosure {i+1} (hex): {disclosure.hex()}")

    def test_spanning_edn_to_cbor_hex(self) -> None:
        """Spanning test: EDN with redaction tags to CBOR hex output."""
        # Complex EDN with multiple redaction scenarios
        edn = """
        {
            1: "https://issuer.example",    / iss /
            2: "https://subject.example",   / sub /
            4: 1725330600,                   / exp /
            5: 1725243840,                   / nbf /
            6: 1725244200,                   / iat /

            / Redacted scalar claim /
            "email": 59("alice@example.com"),

            / Non-redacted claim /
            "role": "admin",

            / Redacted boolean /
            "verified": 59(true),

            / Nested object with partial redaction /
            "address": {
                "street": "123 Main St",
                "city": 59("Seattle"),
                "state": "WA",
                "zip": 59("98101")
            },

            / Array with redacted elements /
            "phones": [
                "555-0100",
                60("555-0101"),
                "555-0102"
            ],

            / Fully redacted object /
            "payment": 59({
                "method": "card",
                "last4": "1234"
            })
        }
        """

        # Fixed salt for reproducible test
        fixed_salt = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"

        with patch("sd_cwt.redaction.generate_salt", return_value=fixed_salt):
            cbor_claims, disclosures = edn_to_redacted_cbor(edn)

        # Convert to hex
        cbor_hex = cbor_claims.hex()

        # Decode to verify structure
        claims = cbor_utils.decode(bytes.fromhex(cbor_hex))

        # Verify non-redacted claims
        assert claims[1] == "https://issuer.example"
        assert claims[2] == "https://subject.example"
        assert claims[4] == 1725330600
        assert claims["role"] == "admin"
        assert claims["address"]["street"] == "123 Main St"
        assert claims["address"]["state"] == "WA"
        assert claims["phones"][0] == "555-0100"
        assert claims["phones"][1] == "555-0102"  # Note: redacted element removed

        # Verify redacted claims are gone
        assert "email" not in claims
        assert "verified" not in claims
        assert "payment" not in claims
        assert "city" not in claims["address"]
        assert "zip" not in claims["address"]

        # Verify SD hashes are present
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in claims
        sd_hashes = claims[simple_59]
        assert isinstance(sd_hashes, list)
        assert len(sd_hashes) == 6  # 6 redacted items

        # Verify disclosures
        assert len(disclosures) == 6

        # Print results for verification
        print(f"\n{'='*60}")
        print("SPANNING TEST RESULTS")
        print(f"{'='*60}")
        print(f"Input EDN length: {len(edn)} characters")
        print(f"Output CBOR hex: {cbor_hex[:100]}...")
        print(f"CBOR hex length: {len(cbor_hex)} characters")
        print(f"CBOR bytes length: {len(cbor_claims)} bytes")
        print(f"Number of redacted claims: {len(disclosures)}")
        print(f"\nDisclosures:")
        for i, disclosure in enumerate(disclosures):
            decoded = cbor_utils.decode(disclosure)
            print(f"  {i+1}. Key: {decoded[2]}, Value: {decoded[1]}")
        print(f"\nFull CBOR hex:\n{cbor_hex}")

        # Return for external verification
        return cbor_hex, [d.hex() for d in disclosures]


class TestSaltGenerators:
    """Test salt generation functionality."""

    def test_secure_salt_generator(self) -> None:
        """Test secure salt generator produces different salts."""
        generator = SecureSaltGenerator()

        salt1 = generator.generate_salt()
        salt2 = generator.generate_salt()

        assert len(salt1) == 16
        assert len(salt2) == 16
        assert salt1 != salt2  # Should be different

        # Test custom length
        salt32 = generator.generate_salt(32)
        assert len(salt32) == 32

    def test_seeded_salt_generator_deterministic(self) -> None:
        """Test seeded salt generator produces deterministic output."""
        generator1 = SeededSaltGenerator(seed=42)
        generator2 = SeededSaltGenerator(seed=42)
        generator3 = SeededSaltGenerator(seed=123)

        # Same seed should produce same salts
        salt1a = generator1.generate_salt()
        salt1b = generator2.generate_salt()
        assert salt1a == salt1b

        # Different seed should produce different salts
        salt3 = generator3.generate_salt()
        assert salt1a != salt3

        # Multiple salts from same generator should be different
        salt1c = generator1.generate_salt()
        assert salt1a != salt1c

    def test_generate_salt_with_custom_generator(self) -> None:
        """Test generate_salt function with custom generator."""
        seeded_gen = SeededSaltGenerator(seed=777)

        # Test with custom generator
        salt1 = generate_salt(salt_generator=seeded_gen)
        salt2 = generate_salt(salt_generator=seeded_gen)

        assert len(salt1) == 16
        assert len(salt2) == 16
        assert salt1 != salt2  # Different calls should give different results

        # Test reproducibility with same seed
        seeded_gen2 = SeededSaltGenerator(seed=777)
        salt3 = generate_salt(salt_generator=seeded_gen2)
        assert salt3 == salt1  # First salt from same seed should match

    def test_deterministic_redaction(self) -> None:
        """Test that redaction with seeded generator is deterministic."""
        edn = """
        {
            "name": 59("Alice"),
            "email": 59("alice@example.com"),
            "age": 30
        }
        """

        seeded_gen1 = SeededSaltGenerator(seed=12345)
        seeded_gen2 = SeededSaltGenerator(seed=12345)

        # Generate with same seed twice
        cbor1, disclosures1 = edn_to_redacted_cbor(edn, seeded_gen1)
        cbor2, disclosures2 = edn_to_redacted_cbor(edn, seeded_gen2)

        # Results should be identical
        assert cbor1 == cbor2
        assert len(disclosures1) == len(disclosures2)
        for d1, d2 in zip(disclosures1, disclosures2):
            assert d1 == d2

        # With different seed, results should be different
        seeded_gen3 = SeededSaltGenerator(seed=54321)
        cbor3, disclosures3 = edn_to_redacted_cbor(edn, seeded_gen3)

        assert cbor1 != cbor3  # Different salts -> different hashes -> different CBOR
        assert disclosures1 != disclosures3

    def test_deterministic_hex_output(self) -> None:
        """Test reproducible hex output for documentation/examples."""
        edn = """
        {
            1: "https://issuer.example",
            2: "user123",
            4: 1725330600,
            "email": 59("alice@example.com"),
            "role": "admin",
            "verified": 59(true)
        }
        """

        # Fixed seed for reproducible documentation
        seeded_gen = SeededSaltGenerator(seed=0x12345678)
        cbor_claims, disclosures = edn_to_redacted_cbor(edn, seeded_gen)

        # Convert to hex
        hex_output = cbor_claims.hex()

        # Verify structure
        claims = cbor_utils.decode(cbor_claims)
        assert claims[1] == "https://issuer.example"
        assert claims[2] == "user123"
        assert claims["role"] == "admin"
        assert "email" not in claims
        assert "verified" not in claims

        # Check that we have expected number of hashes
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in claims
        assert len(claims[simple_59]) == 2  # Two redacted claims

        # Print for documentation (this will be deterministic)
        print(f"\nDeterministic CBOR hex: {hex_output}")
        print(f"Disclosure count: {len(disclosures)}")

        # Verify this is reproducible
        seeded_gen2 = SeededSaltGenerator(seed=0x12345678)
        cbor_claims2, disclosures2 = edn_to_redacted_cbor(edn, seeded_gen2)
        assert cbor_claims == cbor_claims2
        assert disclosures == disclosures2

    def test_secure_vs_seeded_generators(self) -> None:
        """Test that secure and seeded generators behave differently."""
        edn = """
        {
            "test": 59("value")
        }
        """

        # Generate with secure generator twice
        cbor1, _ = edn_to_redacted_cbor(edn)  # Uses secure by default
        cbor2, _ = edn_to_redacted_cbor(edn)  # Uses secure by default

        # Should be different due to random salts
        assert cbor1 != cbor2

        # Generate with seeded generator twice
        seeded_gen1 = SeededSaltGenerator(seed=999)
        seeded_gen2 = SeededSaltGenerator(seed=999)

        cbor3, _ = edn_to_redacted_cbor(edn, seeded_gen1)
        cbor4, _ = edn_to_redacted_cbor(edn, seeded_gen2)

        # Should be identical due to same seed
        assert cbor3 == cbor4