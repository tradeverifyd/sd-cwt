"""Tests for examples from draft-ietf-spice-sd-cwt specification."""

import hashlib
from unittest.mock import patch

import pytest

from sd_cwt import cbor_utils
from sd_cwt.redaction import SeededSaltGenerator, edn_to_redacted_cbor


class TestMinimalSpanningExample:
    """Tests for Section 13.1 - Minimal Spanning Example."""

    def test_minimal_spanning_example_structure(self):
        """Test the minimal spanning example structure from specification."""
        # EDN from Section 13.1 with key redactions and array elements
        minimal_spanning_edn = '''
        {
            1: "https://issuer.example",
            2: "https://device.example",
            4: 1725330600,
            5: 1725243900,
            6: 1725244200,
            8: {
                1: {
                    1: 2,
                    -1: 1,
                    -2: h'8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d',
                    -3: h'4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'
                }
            },
            500: true,
            / Redacted inspector license /
            501: 58("ABCD-123456"),
            502: [
                / Redacted inspection date /
                58(1549560720),
                58(1612498440),
                1674004740
            ],
            503: {
                "country": "us",
                / Redacted region /
                "region": 58("ca"),
                "postal_code": "94188"
            }
        }
        '''

        # Use seeded generator for reproducible results
        seeded_gen = SeededSaltGenerator(seed=0x12345)
        cbor_claims, disclosures = edn_to_redacted_cbor(minimal_spanning_edn, seeded_gen)

        # Decode to verify structure
        claims = cbor_utils.decode(cbor_claims)

        # Verify basic claims remain
        assert claims[1] == "https://issuer.example"
        assert claims[2] == "https://device.example"
        assert claims[4] == 1725330600
        assert claims[500] is True

        # Verify redacted claims are removed
        assert 501 not in claims  # inspector_license_number redacted
        assert "region" not in claims[503]  # region redacted from nested object

        # Verify array redaction - array should have only non-redacted elements
        assert len(claims[502]) == 1  # Only the non-redacted timestamp remains
        assert claims[502][0] == 1674004740

        # Verify we have the correct number of disclosures
        # Should be: inspector license (501), region, and 2 array elements from inspection dates
        assert len(disclosures) == 4

        # Verify simple(59) contains hashes
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in claims
        assert len(claims[simple_59]) == 4  # Four redacted items

    def test_inspector_license_disclosure(self):
        """Test specific disclosure for inspector license number."""
        edn = '{"inspector_license": 58("ABCD-123456")}'

        seeded_gen = SeededSaltGenerator(seed=42)
        cbor_claims, disclosures = edn_to_redacted_cbor(edn, seeded_gen)

        # Verify disclosure structure [salt, value, claim]
        assert len(disclosures) == 1
        disclosure = cbor_utils.decode(disclosures[0])

        assert len(disclosure) == 3
        assert isinstance(disclosure[0], bytes)  # salt
        assert disclosure[1] == "ABCD-123456"    # value
        assert disclosure[2] == "inspector_license"  # claim key

    def test_nested_region_disclosure(self):
        """Test nested region redaction in inspection location."""
        edn = '''
        {
            "inspection_location": {
                "country": "us",
                "region": 58("ca"),
                "postal_code": "94188"
            }
        }
        '''

        seeded_gen = SeededSaltGenerator(seed=123)
        cbor_claims, disclosures = edn_to_redacted_cbor(edn, seeded_gen)

        claims = cbor_utils.decode(cbor_claims)

        # Verify nested structure preserved except redacted claim
        assert claims["inspection_location"]["country"] == "us"
        assert claims["inspection_location"]["postal_code"] == "94188"
        assert "region" not in claims["inspection_location"]

        # Verify disclosure
        assert len(disclosures) == 1
        disclosure = cbor_utils.decode(disclosures[0])
        assert disclosure[1] == "ca"
        assert disclosure[2] == "region"


class TestNestedExample:
    """Tests for Section 13.2 - Nested Example."""

    def test_nested_inspection_history_structure(self):
        """Test multi-level nested redaction in inspection history."""
        # Simplified version focusing on key nested redaction patterns
        nested_edn = '''
        {
            1: "https://issuer.example",
            2: "https://device.example",
            "history": [
                {
                    "status": true,
                    "date": 1549560720,
                    "inspector": 58("DCBA-101777"),
                    "location": {
                        "country": "us",
                        "region": 58("co"),
                        "postal": "80302"
                    }
                }
            ],
            "current_record": {
                "status": true,
                "date": 17183928,
                "inspector": 58("ABCD-123456"),
                "location": 58({
                    "country": "us",
                    "region": "ca",
                    "postal": "94188"
                })
            }
        }
        '''

        seeded_gen = SeededSaltGenerator(seed=0x54321)
        cbor_claims, disclosures = edn_to_redacted_cbor(nested_edn, seeded_gen)

        claims = cbor_utils.decode(cbor_claims)

        # Verify basic structure
        assert claims[1] == "https://issuer.example"
        assert claims[2] == "https://device.example"

        # Verify nested redaction in history array
        history = claims["history"]
        assert len(history) == 1
        first_record = history[0]
        assert first_record["status"] is True
        assert first_record["date"] == 1549560720
        assert "inspector" not in first_record  # redacted
        assert first_record["location"]["country"] == "us"
        assert "region" not in first_record["location"]  # nested redaction
        assert first_record["location"]["postal"] == "80302"

        # Verify redaction of entire nested object
        current = claims["current_record"]
        assert current["status"] is True
        assert current["date"] == 17183928
        assert "inspector" not in current  # redacted
        assert "location" not in current  # entire object redacted

        # Verify we have correct number of disclosures
        assert len(disclosures) == 4  # inspector1, region, inspector2, entire location object

    def test_multi_level_disclosure_verification(self):
        """Test that multi-level disclosures can be properly verified."""
        # Test a simpler nested case where array element is redacted, and within that
        # element there's a nested redacted field
        edn = '''
        {
            "data": 58([
                {
                    "public": "visible",
                    "private": 58("hidden")
                }
            ])
        }
        '''

        seeded_gen = SeededSaltGenerator(seed=999)
        cbor_claims, disclosures = edn_to_redacted_cbor(edn, seeded_gen)

        claims = cbor_utils.decode(cbor_claims)

        # The entire array should be redacted
        assert "data" not in claims

        # Should have 1 disclosure for the array element (which contains both public and private data)
        assert len(disclosures) == 1

        # Verify disclosure content - it should contain the entire array element
        disclosure = cbor_utils.decode(disclosures[0])
        assert disclosure[2] == "data"  # claim key is "data"

        # The disclosure value should be the array element with the nested private field
        disclosed_array = disclosure[1]
        assert isinstance(disclosed_array, list)
        assert len(disclosed_array) == 1

        # The array element should have both public and private fields
        # (since the redaction happens at array level, not field level)
        array_element = disclosed_array[0]
        assert array_element["public"] == "visible"
        assert array_element["private"] == "hidden"


class TestSpecificationKeys:
    """Tests for Appendix C - Keys Used in Examples."""

    def test_holder_key_from_specification(self):
        """Test holder key material from Appendix C.1."""
        # Holder public key from specification (P-256)
        holder_public_key = {
            1: 2,  # kty: EC2
            -1: 1,  # crv: P-256
            -2: bytes.fromhex('8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d'),  # x
            -3: bytes.fromhex('4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'),  # y
        }

        # Test CBOR encoding/decoding
        cbor_key = cbor_utils.encode(holder_public_key)
        decoded_key = cbor_utils.decode(cbor_key)

        assert decoded_key == holder_public_key
        assert decoded_key[1] == 2  # EC2
        assert decoded_key[-1] == 1  # P-256

        # Test key structure
        assert len(decoded_key[-2]) == 32  # x coordinate
        assert len(decoded_key[-3]) == 32  # y coordinate

    def test_issuer_key_from_specification(self):
        """Test issuer key material from Appendix C.2."""
        # Issuer public key from specification (P-384)
        issuer_public_key = {
            1: 2,  # kty: EC2
            -1: 2,  # crv: P-384
            -2: bytes.fromhex('c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf'),  # x
            -3: bytes.fromhex('8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e84a055a31fb7f9214b27509522c159e764f8711e11609554'),  # y
        }

        # Test CBOR encoding/decoding
        cbor_key = cbor_utils.encode(issuer_public_key)
        decoded_key = cbor_utils.decode(cbor_key)

        assert decoded_key == issuer_public_key
        assert decoded_key[1] == 2  # EC2
        assert decoded_key[-1] == 2  # P-384

        # Test key structure
        assert len(decoded_key[-2]) == 48  # x coordinate (P-384)
        assert len(decoded_key[-3]) == 48  # y coordinate (P-384)

    def test_specification_thumbprints(self):
        """Test COSE key thumbprints match specification values."""
        from sd_cwt.thumbprint import CoseKeyThumbprint

        # Holder key thumbprint test
        holder_key = {
            1: 2,  # kty: EC2
            -1: 1,  # crv: P-256
            -2: bytes.fromhex('8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d'),
            -3: bytes.fromhex('4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'),
        }

        holder_thumbprint = CoseKeyThumbprint.compute(holder_key, "sha256")
        expected_holder = bytes.fromhex('8343d73cdfcb81f2c7cd11a5f317be8eb34e4807ec8c9ceb282495cffdf037e0')
        assert holder_thumbprint == expected_holder

        # Issuer key thumbprint test
        issuer_key = {
            1: 2,  # kty: EC2
            -1: 2,  # crv: P-384
            -2: bytes.fromhex('c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf'),
            -3: bytes.fromhex('8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e84a055a31fb7f9214b27509522c159e764f8711e11609554'),
        }

        issuer_thumbprint = CoseKeyThumbprint.compute(issuer_key, "sha256")
        expected_issuer = bytes.fromhex('554550a611c9807b3462cfec4a690a1119bc43b571da1219782133f5fd6dbcb0')
        assert issuer_thumbprint == expected_issuer


class TestSpecificClaimStructures:
    """Tests for specification-specific claim names and structures."""

    def test_numeric_claim_keys(self):
        """Test numeric claim keys used in specification examples."""
        edn = '''
        {
            500: 58(true),
            501: "ABCD-123456",
            502: [1549560720, 58(1612498440), 1674004740],
            503: {
                1: "us",
                2: 58("ca"),
                3: "94188"
            },
            504: 58([{"batch": "data"}])
        }
        '''

        seeded_gen = SeededSaltGenerator(seed=777)
        cbor_claims, disclosures = edn_to_redacted_cbor(edn, seeded_gen)

        claims = cbor_utils.decode(cbor_claims)

        # Verify non-redacted claims
        assert claims[501] == "ABCD-123456"
        assert claims[503][1] == "us"
        assert claims[503][3] == "94188"

        # Verify redacted claims removed
        assert 500 not in claims  # boolean redacted
        assert 504 not in claims  # array redacted
        assert 2 not in claims[503]  # nested region redacted

        # Verify array element redaction
        assert len(claims[502]) == 2  # One element redacted
        assert 1549560720 in claims[502]
        assert 1674004740 in claims[502]
        assert 1612498440 not in claims[502]  # This was redacted

        # Verify disclosures created
        assert len(disclosures) >= 4  # boolean, region, array element, full array

    def test_inspection_dates_array_redaction(self):
        """Test array element redaction for inspection dates."""
        edn = '''
        {
            "inspection_dates": [
                1549560720,
                58(1612498440),
                58(1674004740),
                1700000000
            ]
        }
        '''

        seeded_gen = SeededSaltGenerator(seed=555)
        cbor_claims, disclosures = edn_to_redacted_cbor(edn, seeded_gen)

        claims = cbor_utils.decode(cbor_claims)

        # Array should have only non-redacted elements
        dates = claims["inspection_dates"]
        assert len(dates) == 2  # Two elements redacted
        assert 1549560720 in dates
        assert 1700000000 in dates
        assert 1612498440 not in dates  # redacted
        assert 1674004740 not in dates  # redacted

        # Should have 2 disclosures for the redacted array elements
        array_element_disclosures = 0
        for disclosure_bytes in disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            if isinstance(disclosure[1], int) and disclosure[1] in [1612498440, 1674004740]:
                array_element_disclosures += 1

        assert array_element_disclosures == 2

    def test_redacted_claim_keys_simple_59(self):
        """Test simple(59) usage for redacted claim keys."""
        edn = '''
        {
            "visible": "data",
            "secret1": 58("hidden1"),
            "secret2": 58("hidden2")
        }
        '''

        cbor_claims, disclosures = edn_to_redacted_cbor(edn)
        claims = cbor_utils.decode(cbor_claims)

        # Verify simple(59) contains hashes
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in claims
        assert isinstance(claims[simple_59], list)
        assert len(claims[simple_59]) == 2  # Two redacted claims

        # Each hash should be 32 bytes (SHA-256)
        for hash_value in claims[simple_59]:
            assert isinstance(hash_value, bytes)
            assert len(hash_value) == 32

        # Verify redacted claims not in main structure
        assert "secret1" not in claims
        assert "secret2" not in claims
        assert claims["visible"] == "data"