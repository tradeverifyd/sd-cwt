"""Test EDN-based redaction with deterministic salting for reproducible results."""

from sd_cwt import cbor_utils
from sd_cwt.redaction import (
    SeededSaltGenerator,
    edn_to_redacted_cbor,
    hash_disclosure,
)


class TestEDNRedactionDeterministic:
    """Test EDN redaction with deterministic salting for reproducible validation."""

    def test_simple_map_key_redaction(self):
        """Test redaction of a simple map key with tag 58 -> simple(59)."""
        # EDN with tag 58 for optional claim
        edn_input = """{
            "iss": "https://issuer.example",
            "sub": "https://subject.example",
            "iat": 1725244200,
            "secret_data": 58("confidential_value")
        }"""

        # Use deterministic salt generator for reproducible results
        salt_gen = SeededSaltGenerator(seed=42)
        cbor_bytes, disclosures = edn_to_redacted_cbor(edn_input, salt_gen)

        # Validate CBOR hex representation
        cbor_hex = cbor_bytes.hex()
        assert isinstance(cbor_hex, str)
        assert len(cbor_hex) > 0

        # Decode and validate structure
        decoded_claims = cbor_utils.decode(cbor_bytes)
        assert isinstance(decoded_claims, dict)

        # Check that simple(59) key is present with hash array
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in decoded_claims
        assert isinstance(decoded_claims[simple_59], list)
        assert len(decoded_claims[simple_59]) == 1  # One redacted map key

        # Validate hash in simple(59) array
        redacted_hash = decoded_claims[simple_59][0]
        assert isinstance(redacted_hash, bytes)
        assert len(redacted_hash) == 32  # SHA-256 hash

        # Validate disclosure structure [salt, value, key]
        assert len(disclosures) == 1
        disclosure = cbor_utils.decode(disclosures[0])
        assert isinstance(disclosure, list)
        assert len(disclosure) == 3
        salt, value, key = disclosure
        assert isinstance(salt, bytes)
        assert value == "confidential_value"
        assert key == "secret_data"

        # Validate hash consistency
        computed_hash = hash_disclosure(disclosures[0])
        assert computed_hash == redacted_hash

        # Validate non-redacted claims are preserved
        assert decoded_claims["iss"] == "https://issuer.example"
        assert decoded_claims["sub"] == "https://subject.example"
        assert decoded_claims["iat"] == 1725244200
        assert "secret_data" not in decoded_claims  # Should be redacted

    def test_array_element_redaction(self):
        """Test redaction of array elements with tag 58 -> tag 60."""
        edn_input = """{
            "iss": "https://issuer.example",
            "inspection_dates": [
                1549560720,
                58(1612498440),
                58(1674004740),
                1690000000
            ]
        }"""

        salt_gen = SeededSaltGenerator(seed=100)
        cbor_bytes, disclosures = edn_to_redacted_cbor(edn_input, salt_gen)

        # Decode and validate structure
        decoded_claims = cbor_utils.decode(cbor_bytes)

        # Check array structure with tag 60 replacements
        inspection_dates = decoded_claims["inspection_dates"]
        assert isinstance(inspection_dates, list)
        assert len(inspection_dates) == 4

        # First element should be unredacted
        assert inspection_dates[0] == 1549560720

        # Second and third elements should be tag 60 wrapped hashes
        tag_60_element_1 = inspection_dates[1]
        assert cbor_utils.is_tag(tag_60_element_1)
        assert cbor_utils.get_tag_number(tag_60_element_1) == 60
        hash_1 = cbor_utils.get_tag_value(tag_60_element_1)
        assert isinstance(hash_1, bytes)
        assert len(hash_1) == 32

        tag_60_element_2 = inspection_dates[2]
        assert cbor_utils.is_tag(tag_60_element_2)
        assert cbor_utils.get_tag_number(tag_60_element_2) == 60
        hash_2 = cbor_utils.get_tag_value(tag_60_element_2)
        assert isinstance(hash_2, bytes)
        assert len(hash_2) == 32

        # Fourth element should be unredacted
        assert inspection_dates[3] == 1690000000

        # Validate disclosures for array elements
        assert len(disclosures) == 2

        # First disclosure: [salt, value, index]
        disclosure_1 = cbor_utils.decode(disclosures[0])
        assert len(disclosure_1) == 3
        salt_1, value_1, index_1 = disclosure_1
        assert isinstance(salt_1, bytes)
        assert value_1 == 1612498440
        assert index_1 == 1  # Array index

        # Second disclosure
        disclosure_2 = cbor_utils.decode(disclosures[1])
        salt_2, value_2, index_2 = disclosure_2
        assert value_2 == 1674004740
        assert index_2 == 2  # Array index

        # Validate hash consistency
        computed_hash_1 = hash_disclosure(disclosures[0])
        computed_hash_2 = hash_disclosure(disclosures[1])
        assert computed_hash_1 == hash_1
        assert computed_hash_2 == hash_2

    def test_nested_map_and_array_redaction(self):
        """Test complex nested redaction with both map keys and array elements."""
        edn_input = """{
            "iss": "https://issuer.example",
            "inspection_history": {
                "location": "facility_a",
                "reports": [
                    1549560720,
                    58(1612498440),
                    1674004740
                ],
                "summary": 58("classified summary")
            },
            "sensitive_data": 58("top secret information")
        }"""

        salt_gen = SeededSaltGenerator(seed=200)
        cbor_bytes, disclosures = edn_to_redacted_cbor(edn_input, salt_gen)

        # Decode and validate structure
        decoded_claims = cbor_utils.decode(cbor_bytes)

        # Check that simple(59) contains hashes for redacted map keys
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in decoded_claims
        redacted_hashes = decoded_claims[simple_59]
        assert isinstance(redacted_hashes, list)
        # Should have hash for "summary" and "sensitive_data" keys
        assert len(redacted_hashes) == 2

        # Check inspection_history structure
        inspection_history = decoded_claims["inspection_history"]
        assert inspection_history["location"] == "facility_a"
        assert "summary" not in inspection_history  # Should be redacted

        # Check reports array structure
        reports = inspection_history["reports"]
        assert len(reports) == 3

        # First element should be intact
        assert reports[0] == 1549560720

        # Second element should be tag 60 wrapped (array element redacted)
        tag_60_element = reports[1]
        assert cbor_utils.is_tag(tag_60_element)
        assert cbor_utils.get_tag_number(tag_60_element) == 60

        # Third element should be intact
        assert reports[2] == 1674004740

        # Check that sensitive_data is redacted
        assert "sensitive_data" not in decoded_claims

        # Validate disclosures
        assert len(disclosures) == 3  # summary, sensitive_data, array element

        # Check that we can match disclosure hashes
        disclosure_hashes = [hash_disclosure(d) for d in disclosures]
        for hash_val in redacted_hashes:
            assert hash_val in disclosure_hashes

    def test_deterministic_salt_reproducibility(self):
        """Test that deterministic salting produces identical results."""
        edn_input = """{
            "public": "data",
            "secret": 58("private_value")
        }"""

        # Generate with same seed twice
        salt_gen_1 = SeededSaltGenerator(seed=12345)
        cbor_bytes_1, disclosures_1 = edn_to_redacted_cbor(edn_input, salt_gen_1)

        salt_gen_2 = SeededSaltGenerator(seed=12345)
        cbor_bytes_2, disclosures_2 = edn_to_redacted_cbor(edn_input, salt_gen_2)

        # Results should be identical
        assert cbor_bytes_1 == cbor_bytes_2
        assert len(disclosures_1) == len(disclosures_2)
        for i in range(len(disclosures_1)):
            assert disclosures_1[i] == disclosures_2[i]

        # Hex representations should be identical
        assert cbor_bytes_1.hex() == cbor_bytes_2.hex()

    def test_complex_nested_array_redaction(self):
        """Test redaction within nested arrays and objects."""
        edn_input = """{
            "measurements": [
                [1, 2, 58(3)],
                58([4, 5, 6]),
                [7, 58(8), 9]
            ],
            "metadata": {
                "version": "1.0",
                "confidential": 58("top_secret_data")
            }
        }"""

        salt_gen = SeededSaltGenerator(seed=999)
        cbor_bytes, disclosures = edn_to_redacted_cbor(edn_input, salt_gen)

        decoded_claims = cbor_utils.decode(cbor_bytes)

        # Check measurements array structure
        measurements = decoded_claims["measurements"]
        assert len(measurements) == 3

        # First sub-array: [1, 2, tag_60(hash)]
        sub_array_1 = measurements[0]
        assert sub_array_1[0] == 1
        assert sub_array_1[1] == 2
        assert cbor_utils.is_tag(sub_array_1[2])
        assert cbor_utils.get_tag_number(sub_array_1[2]) == 60

        # Second element: tag_60(hash) for entire array
        tag_60_array = measurements[1]
        assert cbor_utils.is_tag(tag_60_array)
        assert cbor_utils.get_tag_number(tag_60_array) == 60

        # Third sub-array: [7, tag_60(hash), 9]
        sub_array_3 = measurements[2]
        assert sub_array_3[0] == 7
        assert cbor_utils.is_tag(sub_array_3[1])
        assert cbor_utils.get_tag_number(sub_array_3[1]) == 60
        assert sub_array_3[2] == 9

        # Check metadata structure
        metadata = decoded_claims["metadata"]
        assert metadata["version"] == "1.0"
        assert "confidential" not in metadata  # Should be redacted

        # Check simple(59) contains hashes for redacted map keys
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in decoded_claims
        redacted_hashes = decoded_claims[simple_59]
        assert len(redacted_hashes) == 1  # "confidential" key

        # Validate we have the expected number of disclosures
        assert len(disclosures) == 4  # 3 array elements + 1 map key

    def test_edn_string_format_preservation(self):
        """Test that EDN string format is properly handled."""
        edn_input = '{\n  "claim1": "value1",\n  "claim2": 58("secret")\n}'

        salt_gen = SeededSaltGenerator(seed=777)
        cbor_bytes, disclosures = edn_to_redacted_cbor(edn_input, salt_gen)

        # Should parse and process correctly despite formatting
        decoded_claims = cbor_utils.decode(cbor_bytes)
        assert decoded_claims["claim1"] == "value1"
        assert "claim2" not in decoded_claims

        # Should have one disclosure
        assert len(disclosures) == 1
        disclosure = cbor_utils.decode(disclosures[0])
        assert disclosure[1] == "secret"  # value
        assert disclosure[2] == "claim2"  # key

    def test_hex_validation_deterministic(self):
        """Test specific hex validation for reproducible CBOR outputs."""
        edn_input = """{
            "iss": "test",
            "secret": 58("value")
        }"""

        salt_gen = SeededSaltGenerator(seed=1)
        cbor_bytes, disclosures = edn_to_redacted_cbor(edn_input, salt_gen)

        # Get specific hex representation
        cbor_hex = cbor_bytes.hex()

        # Validate it's a proper hex string
        assert all(c in '0123456789abcdef' for c in cbor_hex)
        assert len(cbor_hex) % 2 == 0  # Even length

        # Should be reproducible with same seed
        salt_gen_2 = SeededSaltGenerator(seed=1)
        cbor_bytes_2, _ = edn_to_redacted_cbor(edn_input, salt_gen_2)
        assert cbor_bytes.hex() == cbor_bytes_2.hex()

    def test_mandatory_claims_not_redacted(self):
        """Test that mandatory claims (iss, aud, exp, etc.) cannot be redacted."""
        # Try to redact mandatory claims - should be ignored based on numeric keys
        edn_input = """{
            1: 58("https://issuer.example"),
            3: 58("https://audience.example"),
            4: 58(1725330600),
            6: 58(1725244200),
            8: 58({"kty": 2}),
            "optional_claim": 58("can_be_redacted")
        }"""

        salt_gen = SeededSaltGenerator(seed=555)
        cbor_bytes, disclosures = edn_to_redacted_cbor(edn_input, salt_gen)

        decoded_claims = cbor_utils.decode(cbor_bytes)

        # Mandatory claims should NOT be redacted (tag 58 should be ignored)
        assert decoded_claims[1] == "https://issuer.example"  # iss
        assert decoded_claims[3] == "https://audience.example"  # aud
        assert decoded_claims[4] == 1725330600  # exp
        assert decoded_claims[6] == 1725244200  # iat
        assert decoded_claims[8] == {"kty": 2}  # cnf

        # Optional claim should be redacted
        assert "optional_claim" not in decoded_claims

        # Should only have one disclosure (for optional_claim)
        assert len(disclosures) == 1
        disclosure = cbor_utils.decode(disclosures[0])
        assert disclosure[2] == "optional_claim"

    def test_disclosure_format_validation(self):
        """Test that disclosures follow the correct [salt, value, key] format."""
        edn_input = """{
            "string_claim": 58("string_value"),
            "number_claim": 58(42),
            "object_claim": 58({"nested": "object"}),
            "array_claim": 58(["item1", "item2"])
        }"""

        salt_gen = SeededSaltGenerator(seed=333)
        cbor_bytes, disclosures = edn_to_redacted_cbor(edn_input, salt_gen)

        assert len(disclosures) == 4

        for disclosure_bytes in disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)

            # Validate disclosure format: [salt, value, key]
            assert isinstance(disclosure, list)
            assert len(disclosure) == 3

            salt, value, key = disclosure

            # Validate salt
            assert isinstance(salt, bytes)
            assert len(salt) == 16  # 128 bits

            # Validate key is string
            assert isinstance(key, str)
            assert key in ["string_claim", "number_claim", "object_claim", "array_claim"]

            # Validate value matches expected type
            if key == "string_claim":
                assert value == "string_value"
            elif key == "number_claim":
                assert value == 42
            elif key == "object_claim":
                assert value == {"nested": "object"}
            elif key == "array_claim":
                assert value == ["item1", "item2"]

    def test_cbor_data_model_validation(self):
        """Test validation using dictionaries against specific CBOR data model instances."""
        edn_input = """{
            1: "https://issuer.example",
            2: "https://subject.example",
            6: 1725244200,
            8: {"kty": 2, "crv": 1},
            "custom_claim": 58("redacted_value")
        }"""

        salt_gen = SeededSaltGenerator(seed=888)
        cbor_bytes, disclosures = edn_to_redacted_cbor(edn_input, salt_gen)

        decoded_claims = cbor_utils.decode(cbor_bytes)

        # Validate against expected CBOR data model structure
        expected_structure = {
            1: str,  # iss - string
            2: str,  # sub - string
            6: int,  # iat - integer
            8: dict, # cnf - map
            cbor_utils.create_simple_value(59): list,  # redacted keys array
        }

        for key, expected_type in expected_structure.items():
            assert key in decoded_claims
            assert isinstance(decoded_claims[key], expected_type)

        # Validate specific values
        assert decoded_claims[1] == "https://issuer.example"
        assert decoded_claims[2] == "https://subject.example"
        assert decoded_claims[6] == 1725244200
        assert decoded_claims[8] == {"kty": 2, "crv": 1}

        # Validate redacted claims structure
        simple_59 = cbor_utils.create_simple_value(59)
        redacted_hashes = decoded_claims[simple_59]
        assert len(redacted_hashes) == 1
        assert isinstance(redacted_hashes[0], bytes)
        assert len(redacted_hashes[0]) == 32  # SHA-256

        # Validate custom claim is redacted
        assert "custom_claim" not in decoded_claims

        # Validate disclosure
        assert len(disclosures) == 1
        disclosure = cbor_utils.decode(disclosures[0])
        assert disclosure[1] == "redacted_value"
        assert disclosure[2] == "custom_claim"
