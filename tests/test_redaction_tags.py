"""Test redaction process using tags 58, 59, and 60."""

from sd_cwt import cbor_utils
from sd_cwt.redaction import SeededSaltGenerator, edn_to_redacted_cbor


class TestRedactionTags:
    """Test the redaction tag transformation process."""

    def test_tag_58_to_59_and_60_transformation(self):
        """Test that tag 58 transforms to tag 59 for map keys and tag 60 for array elements."""
        # EDN with both redactable map key and redactable array element using tag 58
        edn_with_redactables = """
        {
            "public_key": "visible_value",
            "private_key": 58("secret_value"),
            "data_array": [
                "item1",
                58("secret_item"),
                "item3"
            ],
            "another_field": "also_visible"
        }
        """

        # Use seeded generator for deterministic results
        seeded_gen = SeededSaltGenerator(seed=12345)
        cbor_claims, disclosures = edn_to_redacted_cbor(edn_with_redactables, seeded_gen)

        # Decode the redacted claims
        claims = cbor_utils.decode(cbor_claims)

        print("Original EDN uses tag 58 for both map key and array element")
        print("After redaction:")

        # Verify that redacted map key is gone from main claims
        assert "private_key" not in claims, "Redacted map key should be removed"
        assert "public_key" in claims, "Non-redacted key should remain"
        assert "another_field" in claims, "Non-redacted key should remain"

        # Verify that redacted array element is replaced with tag 60 hash
        assert len(claims["data_array"]) == 3, "Array should maintain original length"
        assert "item1" in claims["data_array"], "Non-redacted array element should remain"
        assert "item3" in claims["data_array"], "Non-redacted array element should remain"
        assert (
            "secret_item" not in claims["data_array"]
        ), "Original redacted value should not be present"

        # Find the tag 60 element in the array
        tag_60_elements = [
            item for item in claims["data_array"] if cbor_utils.is_tag(item) and item.tag == 60
        ]
        assert len(tag_60_elements) == 1, "Should have exactly one tag 60 element in array"
        assert isinstance(tag_60_elements[0].value, bytes), "Tag 60 should wrap a hash (bytes)"

        # Verify simple(59) contains hashes for redacted map keys
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in claims, "Claims should contain simple(59) for redacted map keys"
        assert isinstance(claims[simple_59], list), "simple(59) should contain list of hashes"

        # Count redacted map keys (should be 1: private_key)
        redacted_map_keys = 0
        for disclosure_bytes in disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            # If the disclosure has a string key, it's a map key
            if isinstance(disclosure[2], str) and disclosure[2] == "private_key":
                redacted_map_keys += 1

        assert redacted_map_keys == 1, "Should have exactly 1 redacted map key"

        # Verify disclosures contain both map key and array element
        assert len(disclosures) == 2, "Should have 2 disclosures: map key + array element"

        # Analyze disclosures to verify structure
        map_key_disclosure = None
        array_element_disclosure = None

        for disclosure_bytes in disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            # disclosure format: [salt, value, claim_key_or_array_value]

            if disclosure[1] == "secret_value":
                map_key_disclosure = disclosure
            elif disclosure[1] == "secret_item":
                array_element_disclosure = disclosure

        assert map_key_disclosure is not None, "Should have disclosure for map key"
        assert array_element_disclosure is not None, "Should have disclosure for array element"

        # Verify disclosure structures
        assert map_key_disclosure[2] == "private_key", "Map key disclosure should have key name"
        assert array_element_disclosure[2] == 1, "Array element disclosure should have array index"

        print("✓ Tag 58 map key 'private_key' → removed from claims, hash in simple(59)")
        print("✓ Tag 58 array element 'secret_item' → replaced with tag 60 wrapped hash")
        print(f"✓ Created {len(disclosures)} disclosures for redacted items")

    def test_tag_meaning_explanation(self):
        """Test that demonstrates the meaning of each tag clearly."""
        # Before redaction: both use tag 58
        edn_before_redaction = """
        {
            "visible": "data",
            "to_be_redacted_key": 58("hidden_key_value"),
            "list": [
                "visible_item",
                58("hidden_array_value")
            ]
        }
        """

        seeded_gen = SeededSaltGenerator(seed=999)
        cbor_claims, disclosures = edn_to_redacted_cbor(edn_before_redaction, seeded_gen)
        claims = cbor_utils.decode(cbor_claims)

        # Tag 58: Used in EDN to mark items as "to be redacted"
        print("Tag 58: Used in EDN input to mark items as 'to be redacted'")
        print("  - Map keys marked with 58() will be selectively disclosed")
        print("  - Array elements marked with 58() will be selectively disclosed")

        # After redaction - map keys go to simple(59)
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in claims
        print("Simple value 59: Used in final CBOR for redacted map key hashes")
        print(f"  - Found {len(claims[simple_59])} hash(es) for redacted map keys")

        # After redaction - array elements are replaced with tag 60 wrapped hashes
        print("Tag 60: Used for redacted array element hashes (in-place replacement)")
        print("  - Array elements marked with 58() are replaced with tag 60 wrapped hashes")
        print("  - Their disclosures allow reconstruction")

        # Verify the transformation
        assert "to_be_redacted_key" not in claims, "Map key with tag 58 should be redacted"
        assert "visible" in claims, "Non-tagged items should remain visible"
        assert (
            len(claims["list"]) == 2
        ), "Array should maintain original length (visible item + tag 60 hash)"
        assert "visible_item" in claims["list"], "Non-tagged array items should remain"

        # Verify the array contains a tag 60 wrapped hash
        tag_60_in_list = [
            item for item in claims["list"] if cbor_utils.is_tag(item) and item.tag == 60
        ]
        assert len(tag_60_in_list) == 1, "Array should contain exactly one tag 60 element"

    def test_multiple_redactions_with_different_types(self):
        """Test multiple redactions showing tag transformations."""
        edn_complex = """
        {
            "issuer": "https://example.com",
            "subject": "user123",
            "secret_field1": 58("secret1"),
            "secret_field2": 58("secret2"),
            "mixed_array": [
                "public1",
                58("secret_array_item1"),
                "public2",
                58("secret_array_item2"),
                "public3"
            ],
            "nested": {
                "visible": true,
                "hidden": 58("nested_secret")
            }
        }
        """

        seeded_gen = SeededSaltGenerator(seed=777)
        cbor_claims, disclosures = edn_to_redacted_cbor(edn_complex, seeded_gen)
        claims = cbor_utils.decode(cbor_claims)

        # Verify transformations
        print("Multiple redaction transformations:")

        # Map keys with tag 58 → simple(59) hashes
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in claims
        print(f"  Map keys (tag 58 → simple 59): {len(claims[simple_59])} hashes")

        # Array elements with tag 58 → replaced with tag 60 wrapped hashes
        original_array_length = 5  # public1, secret1, public2, secret2, public3
        redacted_array_length = len(claims["mixed_array"])
        assert original_array_length == redacted_array_length, "Array length should be preserved"
        tag_60_count = len(
            [item for item in claims["mixed_array"] if cbor_utils.is_tag(item) and item.tag == 60]
        )
        print(
            f"  Array elements (tag 58 → tag 60): {tag_60_count} items replaced with tag 60 hashes"
        )

        # Only map keys get hashes in simple(59) - array elements use tag 60 in-place
        total_redacted_map_keys = 3  # secret_field1, secret_field2, nested.hidden
        assert len(claims[simple_59]) == total_redacted_map_keys

        # Verify specific removals
        assert "secret_field1" not in claims
        assert "secret_field2" not in claims
        assert "hidden" not in claims["nested"]
        assert claims["nested"]["visible"] is True  # Should remain

        # Verify array transformations (maintains original length with tag 60 replacements)
        assert len(claims["mixed_array"]) == 5  # public1, tag60, public2, tag60, public3
        assert "public1" in claims["mixed_array"]
        assert "public2" in claims["mixed_array"]
        assert "public3" in claims["mixed_array"]
        assert "secret_array_item1" not in claims["mixed_array"]
        assert "secret_array_item2" not in claims["mixed_array"]

        # Count tag 60 elements in the array
        tag_60_elements_in_mixed_array = [
            item for item in claims["mixed_array"] if cbor_utils.is_tag(item) and item.tag == 60
        ]
        assert (
            len(tag_60_elements_in_mixed_array) == 2
        ), "Should have exactly 2 tag 60 elements replacing redacted items"

        # Verify disclosures created
        total_expected_disclosures = 5  # 3 map keys + 2 array elements
        assert len(disclosures) == total_expected_disclosures

        print(f"  Total disclosures created: {len(disclosures)}")
        print("✓ All tag 58 items properly transformed to redacted state")

    def test_tag_semantics_documentation(self):
        """Document the exact semantics of each tag for clarity."""
        # This test serves as documentation of the tag system

        documentation = {
            58: "To-be-redacted marker (EDN input only)",
            59: "Redacted map key hashes (CBOR output, simple value)",
            60: "Redacted array element marker (conceptual, for in-place replacement)",
        }

        print("SD-CWT Redaction Tag Semantics:")
        for tag, description in documentation.items():
            print(f"  Tag {tag}: {description}")

        # Demonstrate with minimal example
        minimal_edn = '{"key": 58("value"), "arr": [58("element")]}'

        seeded_gen = SeededSaltGenerator(seed=1)
        cbor_claims, disclosures = edn_to_redacted_cbor(minimal_edn, seeded_gen)
        claims = cbor_utils.decode(cbor_claims)

        # Tag 58 usage verified
        print("\nTag 58 usage (input):")
        print("  - Used to mark both map keys and array elements for redaction")
        print("  - Syntax: 58(value) in EDN")

        # Simple 59 usage verified
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in claims
        print("\nSimple 59 usage (output):")
        print(f"  - Contains hashes of redacted map keys: {len(claims[simple_59])} hash(es)")
        print("  - Used in final CBOR claims structure")

        # Tag 60 conceptual usage
        print("\nTag 60 usage (conceptual):")
        print("  - Used for in-place hash replacement of redacted array elements")
        print("  - In our implementation, array elements are replaced with tag 60 wrapped hashes")
        print("  - Preserves array structure and allows reconstruction")

        # Verify the implementation behavior
        assert "key" not in claims, "Map key should be redacted"
        assert len(claims["arr"]) == 1, "Array should maintain length with tag 60 replacement"

        # Verify the array contains a tag 60 element
        tag_60_in_arr = [
            item for item in claims["arr"] if cbor_utils.is_tag(item) and item.tag == 60
        ]
        assert len(tag_60_in_arr) == 1, "Array should contain exactly one tag 60 element"

        assert len(disclosures) == 2, "Should have disclosures for both redacted items"

        print("\n✓ Tag semantics verified and documented")
