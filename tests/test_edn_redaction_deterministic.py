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

    def test_edn_serialization_examples_for_developers(self):
        """Show complete EDN examples of redacted payloads for developer understanding."""
        # Original EDN with tag 58 annotations
        original_edn = """{
            "iss": "https://issuer.example",
            "sub": "https://subject.example",
            "iat": 1725244200,
            "mandatory_claim": "always_visible",
            "secret_data": 58("confidential_value"),
            "optional_info": 58({"nested": "object", "value": 42}),
            "inspection_dates": [
                1549560720,
                58(1612498440),
                1690000000
            ]
        }"""

        # Generate redacted CBOR with deterministic salt
        salt_gen = SeededSaltGenerator(seed=1337)
        cbor_bytes, disclosures = edn_to_redacted_cbor(original_edn, salt_gen)

        # Get the CBOR hex for export
        cbor_hex = cbor_bytes.hex()
        print("\n=== REDACTED CBOR (hex) ===")
        print(f"{cbor_hex}")

        # Decode to show the redacted structure
        redacted_payload = cbor_utils.decode(cbor_bytes)

        # Show what the redacted EDN looks like conceptually
        print("\n=== ORIGINAL EDN (with tag 58 annotations) ===")
        print(original_edn.strip())

        print("\n=== REDACTED EDN STRUCTURE (after processing) ===")
        # Build the redacted EDN representation for display
        simple_59 = cbor_utils.create_simple_value(59)

        # Format the inspection dates array showing tag 60
        inspection_dates = redacted_payload["inspection_dates"]
        formatted_dates = []
        for _i, date in enumerate(inspection_dates):
            if cbor_utils.is_tag(date) and cbor_utils.get_tag_number(date) == 60:
                hash_value = cbor_utils.get_tag_value(date)
                formatted_dates.append(f'60(h\'{hash_value.hex()[:16]}...\')')  # Show first 16 hex chars
            else:
                formatted_dates.append(str(date))

        # Format the simple(59) hash array
        hash_array = redacted_payload[simple_59]
        formatted_hashes = []
        for hash_bytes in hash_array:
            formatted_hashes.append(f'h\'{hash_bytes.hex()[:16]}...\'')  # Show first 16 hex chars

        redacted_edn_display = f"""{{
    "iss": "https://issuer.example",
    "sub": "https://subject.example",
    "iat": 1725244200,
    "mandatory_claim": "always_visible",
    "inspection_dates": [{', '.join(formatted_dates)}],
    simple(59): [{', '.join(formatted_hashes)}]
}}"""

        print(redacted_edn_display)

        print("\n=== DISCLOSURES (salt, value, key format) ===")
        for i, disclosure_bytes in enumerate(disclosures):
            disclosure = cbor_utils.decode(disclosure_bytes)
            salt_hex = disclosure[0].hex()[:16]  # First 16 hex chars
            value = disclosure[1]
            key = disclosure[2]
            if isinstance(value, dict):
                value_str = str(value)
            elif isinstance(value, str):
                value_str = f'"{value}"'
            else:
                value_str = str(value)
            print(f"Disclosure {i+1}: [h'{salt_hex}...', {value_str}, \"{key}\"]")

        # Validation assertions for developers to understand behavior
        print("\n=== VALIDATION CHECKS ===")

        # Check that tag 58 map keys became simple(59) entries
        assert simple_59 in redacted_payload, "simple(59) should contain hashes of redacted map keys"
        assert len(redacted_payload[simple_59]) == 2, "Should have 2 redacted map keys"
        print("✓ Tag 58 map keys -> simple(59) hash array")

        # Check that tag 58 array element became tag 60
        tag_60_element = inspection_dates[1]
        assert cbor_utils.is_tag(tag_60_element), "Array element should be wrapped in tag"
        assert cbor_utils.get_tag_number(tag_60_element) == 60, "Should be tag 60"
        print("✓ Tag 58 array element -> tag 60 wrapped hash")

        # Check that mandatory claims are preserved
        assert redacted_payload["iss"] == "https://issuer.example"
        assert redacted_payload["mandatory_claim"] == "always_visible"
        print("✓ Mandatory claims preserved without redaction")

        # Check that optional claims are absent from payload
        assert "secret_data" not in redacted_payload
        assert "optional_info" not in redacted_payload
        print("✓ Optional claims removed from payload (available via disclosures)")

        # Verify disclosure format
        assert len(disclosures) == 3, "Should have 3 disclosures (2 map keys + 1 array element)"
        for disclosure_bytes in disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            assert len(disclosure) == 3, "Each disclosure should be [salt, value, key]"
            assert isinstance(disclosure[0], bytes), "Salt should be bytes"
            assert len(disclosure[0]) == 16, "Salt should be 16 bytes (128 bits)"
        print("✓ Disclosures follow [salt, value, key] format")

        # Show hash consistency
        for i, disclosure_bytes in enumerate(disclosures):
            computed_hash = hash_disclosure(disclosure_bytes)
            disclosure = cbor_utils.decode(disclosure_bytes)

            if isinstance(disclosure[2], str):  # Map key disclosure
                assert computed_hash in redacted_payload[simple_59]
                print(f"✓ Disclosure {i+1} hash matches simple(59) entry")
            elif isinstance(disclosure[2], int):  # Array element disclosure
                array_index = disclosure[2]
                tag_60_hash = cbor_utils.get_tag_value(inspection_dates[array_index])
                assert computed_hash == tag_60_hash
                print(f"✓ Disclosure {i+1} hash matches tag 60 in array[{array_index}]")

        print("\n=== CBOR EXPORT ===")
        print(f"CBOR bytes length: {len(cbor_bytes)}")
        print(f"Hex representation: {cbor_hex}")

        # String comparison checks for exact behavior validation
        expected_mandatory_claims = ["iss", "sub", "iat", "mandatory_claim"]
        for claim in expected_mandatory_claims:
            assert claim in redacted_payload, f"Mandatory claim '{claim}' should be present"

        redacted_claims = ["secret_data", "optional_info"]
        for claim in redacted_claims:
            assert claim not in redacted_payload, f"Redacted claim '{claim}' should be absent"

        print("✓ All string comparison checks passed")
        print("✓ EDN serialization example complete - developers can see exact transformation")

    def test_disclosed_payload_reconstruction_example(self):
        """Show how disclosed payloads are reconstructed from redacted CBOR + disclosures."""
        # Same input as previous test for consistency
        original_edn = """{
            "company": "ACME Corp",
            "product_info": {
                "name": "Widget Pro",
                "version": "2.1.0"
            },
            "confidential": 58("trade_secret_formula"),
            "customer_list": 58(["CustomerA", "CustomerB", "CustomerC"]),
            "metrics": [
                100,
                58(250),
                300
            ]
        }"""

        # Generate redacted CBOR
        salt_gen = SeededSaltGenerator(seed=2024)
        redacted_cbor_bytes, all_disclosures = edn_to_redacted_cbor(original_edn, salt_gen)

        print("\n=== ORIGINAL EDN ===")
        print(original_edn.strip())

        # Show redacted structure
        redacted_payload = cbor_utils.decode(redacted_cbor_bytes)
        simple_59 = cbor_utils.create_simple_value(59)

        print("\n=== REDACTED CBOR STRUCTURE ===")
        print(f"Company: {redacted_payload['company']}")
        print(f"Product info: {redacted_payload['product_info']}")
        print(f"Metrics array: {redacted_payload['metrics']}")

        # Show which items were redacted
        metrics = redacted_payload['metrics']
        metrics_display = []
        for item in metrics:
            if cbor_utils.is_tag(item) and cbor_utils.get_tag_number(item) == 60:
                hash_val = cbor_utils.get_tag_value(item)
                metrics_display.append(f'60(h\'{hash_val.hex()[:12]}...\')')
            else:
                metrics_display.append(str(item))

        hash_array = redacted_payload[simple_59]
        hash_display = [f'h\'{h.hex()[:12]}...\'' for h in hash_array]

        print(f"Metrics with tag 60: [{', '.join(metrics_display)}]")
        print(f"Simple(59) hashes: [{', '.join(hash_display)}]")
        print("Missing claims: confidential, customer_list (in disclosures)")

        # Simulate selective disclosure - choose which items to reveal
        print("\n=== SELECTIVE DISCLOSURE SCENARIOS ===")

        # Scenario 1: Disclose only "confidential"
        selected_disclosures_1 = []
        revealed_claims_1 = {}

        for disclosure_bytes in all_disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            salt, value, key = disclosure
            if key == "confidential":
                selected_disclosures_1.append(disclosure_bytes)
                revealed_claims_1[key] = value

        print("Scenario 1 - Reveal 'confidential' only:")
        print(f"  Disclosed: confidential = \"{revealed_claims_1['confidential']}\"")
        print("  Still hidden: customer_list, metrics[1]")

        # Scenario 2: Disclose "customer_list" and array element
        selected_disclosures_2 = []
        revealed_claims_2 = {}
        revealed_array_elements_2 = {}

        for disclosure_bytes in all_disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            salt, value, key = disclosure
            if key == "customer_list":
                selected_disclosures_2.append(disclosure_bytes)
                revealed_claims_2[key] = value
            elif key == 1:  # Array index 1
                selected_disclosures_2.append(disclosure_bytes)
                revealed_array_elements_2[key] = value

        print("Scenario 2 - Reveal 'customer_list' and metrics[1]:")
        print(f"  Disclosed: customer_list = {revealed_claims_2['customer_list']}")
        print(f"  Disclosed: metrics[1] = {revealed_array_elements_2[1]}")
        print("  Still hidden: confidential")

        # Show complete reconstructed payload for Scenario 2
        print("\n=== RECONSTRUCTED PAYLOAD (Scenario 2) ===")
        # reconstructed_payload = {
        #     "company": redacted_payload["company"],
        #     "product_info": redacted_payload["product_info"],
        #     "customer_list": revealed_claims_2["customer_list"],  # From disclosure
        #     "metrics": [
        #         metrics[0],  # Original value 100
        #         revealed_array_elements_2[1],  # From disclosure: 250
        #         metrics[2]   # Original value 300
        #     ]
        #     # "confidential" still missing - not disclosed
        # }

        reconstructed_edn = """{
    "company": "ACME Corp",
    "product_info": {
        "name": "Widget Pro",
        "version": "2.1.0"
    },
    "customer_list": ["CustomerA", "CustomerB", "CustomerC"],
    "metrics": [100, 250, 300]
}"""
        print(reconstructed_edn.strip())

        # Export the CBOR bytes for both scenarios
        print("\n=== CBOR EXPORTS ===")
        print(f"Original redacted CBOR: {redacted_cbor_bytes.hex()}")
        print(f"Length: {len(redacted_cbor_bytes)} bytes")

        # Validation assertions for string comparisons
        assert "company" in redacted_payload
        assert "confidential" not in redacted_payload
        assert "customer_list" not in redacted_payload
        assert redacted_payload["company"] == "ACME Corp"

        # Check disclosures contain expected data
        disclosure_keys = []
        disclosure_values = []
        for disclosure_bytes in all_disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            disclosure_keys.append(disclosure[2])
            disclosure_values.append(disclosure[1])

        assert "confidential" in disclosure_keys
        assert "customer_list" in disclosure_keys
        assert 1 in disclosure_keys  # Array index
        assert "trade_secret_formula" in disclosure_values
        assert ["CustomerA", "CustomerB", "CustomerC"] in disclosure_values
        assert 250 in disclosure_values

        print("✓ String comparison validations passed")
        print("✓ Developers can now understand redacted vs disclosed payload structures")

    def test_complete_before_after_edn_comparison(self):
        """Complete before/after EDN comparison showing exact transformation."""
        # Original EDN input with tag 58 annotations
        original_edn = """{
            "iss": "https://manufacturer.example",
            "sub": "https://buyer.example",
            "iat": 1703980800,
            "product": "Steel Rebar",
            "batch": "B2024-001",
            "secret_formula": 58("proprietary_mix_v3.2"),
            "test_results": {
                "strength": 520,
                "flexibility": 58(85.5),
                "internal_notes": 58("passed_with_concerns")
            },
            "measurements": [
                10.5,
                58(15.2),
                20.0,
                58(25.8)
            ]
        }"""

        salt_gen = SeededSaltGenerator(seed=12345)
        cbor_bytes, disclosures = edn_to_redacted_cbor(original_edn, salt_gen)
        redacted_payload = cbor_utils.decode(cbor_bytes)

        print("\n" + "="*80)
        print("COMPLETE BEFORE/AFTER EDN TRANSFORMATION COMPARISON")
        print("="*80)

        print("\n>>> BEFORE: Original EDN with tag 58 annotations <<<")
        print(original_edn.strip())

        # Build the after representation
        simple_59 = cbor_utils.create_simple_value(59)
        measurements = redacted_payload["measurements"]
        test_results = redacted_payload["test_results"]

        # Format measurements array
        measurements_formatted = []
        for item in measurements:
            if cbor_utils.is_tag(item) and cbor_utils.get_tag_number(item) == 60:
                hash_val = cbor_utils.get_tag_value(item)
                measurements_formatted.append(f'60(h\'{hash_val.hex()[:8]}...\')')
            else:
                measurements_formatted.append(str(item))

        # Format simple(59) hashes
        hash_array = redacted_payload[simple_59]
        formatted_hashes = []
        for hash_bytes in hash_array:
            formatted_hashes.append(f'h\'{hash_bytes.hex()[:8]}...\'')

        redacted_edn_display = f"""{{
    "iss": "{redacted_payload['iss']}",
    "sub": "{redacted_payload['sub']}",
    "iat": {redacted_payload['iat']},
    "product": "{redacted_payload['product']}",
    "batch": "{redacted_payload['batch']}",
    "test_results": {{
        "strength": {test_results['strength']}
    }},
    "measurements": [{', '.join(measurements_formatted)}],
    simple(59): [{', '.join(formatted_hashes)}]
}}"""

        print("\n>>> AFTER: Redacted CBOR structure (as EDN) <<<")
        print(redacted_edn_display.strip())

        print("\n>>> KEY TRANSFORMATIONS <<<")
        print("• Tag 58 map keys → simple(59) hash array entries")
        print("• Tag 58 array elements → tag 60 wrapped hashes")
        print("• Redacted values moved to separate disclosures")
        print("• Mandatory claims preserved as-is")

        print("\n>>> CBOR HEX EXPORT <<<")
        cbor_hex = cbor_bytes.hex()
        print(f"Length: {len(cbor_bytes)} bytes")
        print(f"Hex: {cbor_hex}")

        print("\n>>> DISCLOSURES BREAKDOWN <<<")
        for i, disclosure_bytes in enumerate(disclosures, 1):
            disclosure = cbor_utils.decode(disclosure_bytes)
            salt, value, key = disclosure
            salt_display = salt.hex()[:8] + "..."

            if isinstance(value, str):
                value_display = f'"{value}"'
            elif isinstance(key, int):
                value_display = f"{value} (array element at index {key})"
            else:
                value_display = str(value)

            key_display = f'"{key}"' if isinstance(key, str) else f"array[{key}]"
            print(f"  {i}. [{salt_display}, {value_display}, {key_display}]")

        # String comparison assertions
        print("\n>>> VALIDATION ASSERTIONS <<<")

        # Check preserved claims
        preserved_claims = ["iss", "sub", "iat", "product", "batch"]
        for claim in preserved_claims:
            assert claim in redacted_payload, f"Claim '{claim}' should be preserved"
        print("✓ Mandatory claims preserved")

        # Check redacted claims
        redacted_claims = ["secret_formula"]
        for claim in redacted_claims:
            assert claim not in redacted_payload, f"Claim '{claim}' should be redacted"
        print("✓ Tagged claims properly redacted")

        # Check partially redacted objects
        assert "test_results" in redacted_payload
        assert "strength" in redacted_payload["test_results"]
        assert "flexibility" not in redacted_payload["test_results"]
        assert "internal_notes" not in redacted_payload["test_results"]
        print("✓ Nested objects partially redacted correctly")

        # Check array transformations
        assert len(measurements) == 4
        assert measurements[0] == 10.5  # Preserved
        assert cbor_utils.is_tag(measurements[1])  # Tag 60
        assert measurements[2] == 20.0  # Preserved
        assert cbor_utils.is_tag(measurements[3])  # Tag 60
        print("✓ Array elements transformed correctly")

        # Check simple(59) structure
        assert simple_59 in redacted_payload
        assert isinstance(redacted_payload[simple_59], list)
        assert len(redacted_payload[simple_59]) == 3  # 3 redacted map keys
        print("✓ Simple(59) contains correct number of hashes")

        # Check disclosure count and format
        assert len(disclosures) == 5  # 3 map keys + 2 array elements
        for disclosure_bytes in disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            assert len(disclosure) == 3
            assert isinstance(disclosure[0], bytes)
            assert len(disclosure[0]) == 16  # 128-bit salt
        print("✓ All disclosures properly formatted")

        print("\n✓ Complete before/after comparison successful!")
        print("✓ Developers can see exact EDN transformation with CBOR exports")

