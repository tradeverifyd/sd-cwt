"""Comprehensive test demonstrating EDN-based APIs for selective disclosure."""

from sd_cwt import (
    SDCWTIssuer,
    SDCWTPresenter,
    SDCWTVerifier,
    cbor_utils,
    cose_key_kid_resolver,
    select_disclosures_by_claim_names,
)
from sd_cwt.redaction import SeededSaltGenerator, edn_to_redacted_cbor, hash_disclosure
from sd_cwt.thumbprint import CoseKeyThumbprint


class TestEDNAPIComprehensive:
    """Comprehensive test suite for EDN-based selective disclosure APIs."""

    def test_complete_edn_workflow_with_deterministic_validation(self):
        """Test complete workflow with EDN specification, deterministic salting, and validation."""

        # Step 1: Define static keys for reproducible testing
        issuer_key_cbor = bytes.fromhex(
            "a60102032620012158203884a05a20e85fc48e34b761d651a74ee8a1ba5e11d7e771f1bc611ee84d05e2225820a0ae4064b94ec449d53218086d37f436b8ef60eb1da6ad50bff700c6ecf613cd23582067b8ee92d2bcd650d6d0632534910250aaee4f192b48218077084e6a04560b62"
        )
        holder_key_cbor = bytes.fromhex(
            "a601020326200121582091e48079742cce0ef9126cfdc526d395dc2136e40deb8c47638bdcf5d7eaa56422582014279156a8e5afa6524192c16660039edb12d581e0c437bf3faa66dca9a5a278235820024b0357a9a9fa0b236cc2c100a23f2bfd822cbed11ec6bbeefe874a6de324ea"
        )

        issuer_key_dict = cbor_utils.decode(issuer_key_cbor)
        holder_key_dict = cbor_utils.decode(holder_key_cbor)

        # Extract holder public key
        holder_public_key = holder_key_dict.copy()
        if -4 in holder_public_key:
            del holder_public_key[-4]
        # holder_public_key_cbor = cbor_utils.encode(holder_public_key)  # Not used in this test

        # Step 2: Create EDN with mandatory and optional claims (matching specification examples)
        edn_specification = """{
            1: "https://steel-manufacturer.example",
            2: "https://customs-broker.example",
            6: 1725244200,
            8: {
                1: {
                    1: 2,
                    -1: 1,
                    -2: h'91e48079742cce0ef9126cfdc526d395dc2136e40deb8c47638bdcf5d7eaa564',
                    -3: h'14279156a8e5afa6524192c16660039edb12d581e0c437bf3faa66dca9a5a278'
                }
            },
            11: "https://steel.consortium.example/rebar/v1.cddl",
            "production_date": "2024-01-15",
            "steel_grade": "ASTM A615 Grade 60",
            "heat_number": 58("H240115-001"),
            "chemical_composition": 58({
                "carbon": 0.25,
                "manganese": 1.20,
                "phosphorus": 0.040,
                "sulfur": 0.050
            }),
            "production_cost": 58(850.75),
            "quality_test_results": 58({
                "tensile_strength": 420,
                "yield_strength": 350,
                "elongation": 18.5
            }),
            "inspection_dates": [
                1549560720,
                58(1612498440),
                58(1674004740),
                1690000000
            ]
        }"""

        # Step 3: Convert EDN to redacted CBOR with deterministic salting
        salt_generator = SeededSaltGenerator(seed=42)
        cbor_bytes, disclosures = edn_to_redacted_cbor(edn_specification, salt_generator)

        # Step 4: Validate CBOR hex representation
        cbor_hex = cbor_bytes.hex()
        assert isinstance(cbor_hex, str)
        assert len(cbor_hex) > 100  # Should be substantial

        # Step 5: Validate redacted CBOR structure
        decoded_claims = cbor_utils.decode(cbor_bytes)

        # Check mandatory claims are preserved
        assert decoded_claims[1] == "https://steel-manufacturer.example"  # iss
        assert decoded_claims[2] == "https://customs-broker.example"  # sub
        assert decoded_claims[6] == 1725244200  # iat
        assert 8 in decoded_claims  # cnf
        assert decoded_claims[11] == "https://steel.consortium.example/rebar/v1.cddl"  # vct
        assert decoded_claims["production_date"] == "2024-01-15"
        assert decoded_claims["steel_grade"] == "ASTM A615 Grade 60"

        # Check optional claims are redacted (not present in payload)
        assert "heat_number" not in decoded_claims
        assert "chemical_composition" not in decoded_claims
        assert "production_cost" not in decoded_claims
        assert "quality_test_results" not in decoded_claims

        # Check simple(59) contains hashes for redacted map keys
        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in decoded_claims
        redacted_hashes = decoded_claims[simple_59]
        assert isinstance(redacted_hashes, list)
        assert len(redacted_hashes) == 4  # 4 redacted map keys

        # Check array has tag 60 elements for redacted items
        inspection_dates = decoded_claims["inspection_dates"]
        assert len(inspection_dates) == 4
        assert inspection_dates[0] == 1549560720  # unredacted
        assert cbor_utils.is_tag(inspection_dates[1])  # tag 60
        assert cbor_utils.get_tag_number(inspection_dates[1]) == 60
        assert cbor_utils.is_tag(inspection_dates[2])  # tag 60
        assert cbor_utils.get_tag_number(inspection_dates[2]) == 60
        assert inspection_dates[3] == 1690000000  # unredacted

        # Step 6: Validate disclosures format and content
        assert len(disclosures) == 6  # 4 map keys + 2 array elements

        disclosure_claims = {}
        for disclosure_bytes in disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            assert len(disclosure) == 3  # [salt, value, key]
            salt, value, key = disclosure
            assert isinstance(salt, bytes)
            assert len(salt) == 16  # 128-bit salt

            if isinstance(key, str):
                disclosure_claims[key] = value

        # Validate specific disclosure values
        assert disclosure_claims["heat_number"] == "H240115-001"
        assert disclosure_claims["chemical_composition"] == {
            "carbon": 0.25,
            "manganese": 1.20,
            "phosphorus": 0.040,
            "sulfur": 0.050,
        }
        assert disclosure_claims["production_cost"] == 850.75
        assert disclosure_claims["quality_test_results"] == {
            "tensile_strength": 420,
            "yield_strength": 350,
            "elongation": 18.5,
        }

        # Step 7: Test hash consistency
        for disclosure_bytes in disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            computed_hash = hash_disclosure(disclosure_bytes)

            if isinstance(disclosure[2], str):  # Map key disclosure
                assert computed_hash in redacted_hashes
            elif isinstance(disclosure[2], int):  # Array element disclosure
                # Find corresponding tag 60 hash in array
                array_index = disclosure[2]
                tag_60_element = inspection_dates[array_index]
                array_hash = cbor_utils.get_tag_value(tag_60_element)
                assert computed_hash == array_hash

        # Step 8: Create SD-CWT using high-level API
        issuer = SDCWTIssuer(issuer_key_dict)

        # Bypass the EDN creation step since we already have the CBOR and disclosures
        # Create SD-CWT directly from the redacted claims
        issuer_thumbprint = CoseKeyThumbprint.compute(issuer_key_dict, "sha256")
        protected_header = {
            1: -7,  # ES256
            16: "application/sd-cwt",  # typ
            4: issuer_thumbprint,  # kid
        }

        from sd_cwt.cose_sign1 import cose_sign1_sign

        sd_cwt = cose_sign1_sign(cbor_bytes, issuer.signer, protected_header=protected_header)

        # Step 9: Test presentation with selective disclosure
        presenter = SDCWTPresenter(holder_key_dict)

        # Select specific claims to disclose
        selected_claim_names = ["heat_number", "chemical_composition"]
        selected_disclosures = select_disclosures_by_claim_names(disclosures, selected_claim_names)

        # Validate selected disclosures
        assert len(selected_disclosures) == 2

        for disclosure_bytes in selected_disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            assert disclosure[2] in selected_claim_names

        # Create presentation
        kbt = presenter.create_presentation(
            sd_cwt=sd_cwt,
            disclosures=disclosures,
            selected_disclosures=selected_disclosures,
            audience="https://customs.us.example",
            nonce="test_nonce_123",
        )

        # Step 10: Test verification
        issuer_thumbprint = CoseKeyThumbprint.compute(issuer_key_dict, "sha256")
        issuer_kid_pairs = [(issuer_thumbprint, issuer_key_cbor)]
        issuer_resolver = cose_key_kid_resolver(issuer_kid_pairs)

        verifier = SDCWTVerifier(issuer_resolver)
        is_valid, verified_claims, tags_absent = verifier.verify_presentation(
            kbt=kbt, expected_audience="https://customs.us.example"
        )

        # Step 11: Validate verification results
        assert is_valid, "Presentation should be cryptographically valid"
        assert verified_claims is not None, "Should extract verified claims"
        assert tags_absent, "No redaction tags should be present in final claims"

        # Validate mandatory claims are present
        assert verified_claims["iss"] == "https://steel-manufacturer.example"
        assert verified_claims["sub"] == "https://customs-broker.example"
        assert verified_claims["iat"] == 1725244200
        assert verified_claims["production_date"] == "2024-01-15"
        assert verified_claims["steel_grade"] == "ASTM A615 Grade 60"

        # Validate selected claims are disclosed
        assert verified_claims["heat_number"] == "H240115-001"
        assert verified_claims["chemical_composition"] == {
            "carbon": 0.25,
            "manganese": 1.20,
            "phosphorus": 0.040,
            "sulfur": 0.050,
        }

        # Validate non-selected claims are NOT disclosed
        assert "production_cost" not in verified_claims
        assert "quality_test_results" not in verified_claims

        # Step 12: Test reproducibility
        salt_generator_2 = SeededSaltGenerator(seed=42)
        cbor_bytes_2, disclosures_2 = edn_to_redacted_cbor(edn_specification, salt_generator_2)

        assert cbor_bytes.hex() == cbor_bytes_2.hex(), "Should be reproducible with same seed"
        assert len(disclosures) == len(disclosures_2), "Same number of disclosures"

    def test_edn_api_validation_patterns(self):
        """Test various validation patterns for EDN-based APIs."""

        # Test 1: Complex nested structures
        nested_edn = """{
            "public_info": {
                "company": "Example Corp",
                "address": {
                    "country": "US",
                    "state": "CA",
                    "postal_code": 58("94102")
                }
            },
            "employee_data": [
                "Alice Engineer",
                58("Bob Manager"),
                "Carol Director"
            ],
            "confidential": 58("top_secret_data")
        }"""

        salt_gen = SeededSaltGenerator(seed=999)
        cbor_bytes, disclosures = edn_to_redacted_cbor(nested_edn, salt_gen)
        decoded = cbor_utils.decode(cbor_bytes)

        # Validate nested structure preservation
        assert decoded["public_info"]["company"] == "Example Corp"
        assert decoded["public_info"]["address"]["country"] == "US"
        assert decoded["public_info"]["address"]["state"] == "CA"
        assert "postal_code" not in decoded["public_info"]["address"]

        # Validate array redaction
        employee_data = decoded["employee_data"]
        assert employee_data[0] == "Alice Engineer"
        assert cbor_utils.is_tag(employee_data[1])  # Should be tag 60
        assert employee_data[2] == "Carol Director"

        # Test 2: Disclosure filtering by name
        all_disclosure_names = []
        for disclosure_bytes in disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            if isinstance(disclosure[2], str):
                all_disclosure_names.append(disclosure[2])

        selected_names = ["postal_code"]
        filtered_disclosures = select_disclosures_by_claim_names(disclosures, selected_names)
        assert len(filtered_disclosures) == 1

        filtered_disclosure = cbor_utils.decode(filtered_disclosures[0])
        assert filtered_disclosure[2] == "postal_code"
        assert filtered_disclosure[1] == "94102"

        # Test 3: CBOR data model validation
        expected_types = {
            "public_info": dict,
            "employee_data": list,
            cbor_utils.create_simple_value(59): list,
        }

        for key, expected_type in expected_types.items():
            assert key in decoded
            assert isinstance(decoded[key], expected_type)

    def test_hex_and_dictionary_validation(self):
        """Test specific hex bytestring and dictionary validation requirements."""

        edn_input = """{
            "string_claim": 58("test_string"),
            "number_claim": 58(42),
            "boolean_claim": 58(true),
            "array_claim": [1, 58(2), 3],
            "object_claim": {
                "public": "visible",
                "private": 58("hidden")
            }
        }"""

        salt_gen = SeededSaltGenerator(seed=123)
        cbor_bytes, disclosures = edn_to_redacted_cbor(edn_input, salt_gen)

        # Hex validation
        hex_string = cbor_bytes.hex()
        assert len(hex_string) % 2 == 0  # Even length
        assert all(c in "0123456789abcdef" for c in hex_string)

        # Specific hex pattern validation (deterministic with seed 123)
        assert hex_string.startswith("a")  # CBOR map marker

        # Dictionary validation
        decoded = cbor_utils.decode(cbor_bytes)

        # Validate specific CBOR data model instances
        validation_dict = {
            "string_claim": (False, str),  # Should be redacted
            "number_claim": (False, int),  # Should be redacted
            "boolean_claim": (False, bool),  # Should be redacted
            "array_claim": (True, list),  # Should be present (contains tag 60)
            "object_claim": (True, dict),  # Should be present (nested "private" redacted)
            cbor_utils.create_simple_value(59): (True, list),  # Redacted hashes
        }

        for key, (should_be_present, expected_type) in validation_dict.items():
            if should_be_present:
                assert key in decoded, f"Key {key} should be present"
                assert isinstance(
                    decoded[key], expected_type
                ), f"Key {key} should be {expected_type}"
            else:
                assert key not in decoded, f"Key {key} should be redacted"

        # Validate array structure with tag 60
        array_claim = decoded["array_claim"]
        assert array_claim[0] == 1
        assert cbor_utils.is_tag(array_claim[1])
        assert cbor_utils.get_tag_number(array_claim[1]) == 60
        assert array_claim[2] == 3

        # Validate nested object redaction
        object_claim = decoded["object_claim"]
        assert object_claim["public"] == "visible"
        assert "private" not in object_claim

        # Validate disclosure count and format
        assert len(disclosures) == 5  # 4 map keys + 1 array element

        for _i, disclosure_bytes in enumerate(disclosures):
            # Validate each disclosure is proper CBOR
            disclosure_hex = disclosure_bytes.hex()
            assert len(disclosure_hex) > 0

            # Validate structure
            disclosure = cbor_utils.decode(disclosure_bytes)
            assert isinstance(disclosure, list)
            assert len(disclosure) == 3

            salt, value, key = disclosure
            assert isinstance(salt, bytes)
            assert len(salt) == 16  # 128-bit salt

            # Validate key-value consistency
            if key == "string_claim":
                assert value == "test_string"
            elif key == "number_claim":
                assert value == 42
            elif key == "boolean_claim":
                assert value is True
            elif key == 1:  # Array index
                assert value == 2

    def test_specification_compliance_validation(self):
        """Test compliance with SD-CWT specification requirements."""

        # Test mandatory claim protection
        edn_with_mandatory = """{
            1: 58("https://protected-issuer.example"),
            3: 58("https://protected-audience.example"),
            6: 58(1725244200),
            8: 58({"protected": "cnf_claim"}),
            39: 58("protected_cnonce"),
            "custom_claim": 58("can_be_redacted")
        }"""

        salt_gen = SeededSaltGenerator(seed=456)
        cbor_bytes, disclosures = edn_to_redacted_cbor(edn_with_mandatory, salt_gen)
        decoded = cbor_utils.decode(cbor_bytes)

        # Mandatory claims should NOT be redacted per specification
        assert decoded[1] == "https://protected-issuer.example"  # iss
        assert decoded[3] == "https://protected-audience.example"  # aud
        assert decoded[6] == 1725244200  # iat
        assert decoded[8] == {"protected": "cnf_claim"}  # cnf
        assert decoded[39] == "protected_cnonce"  # cnonce

        # Only custom claim should be redacted
        assert "custom_claim" not in decoded
        assert len(disclosures) == 1

        # Validate disclosure format matches specification [salt, value, key]
        disclosure = cbor_utils.decode(disclosures[0])
        assert disclosure[0]  # salt (non-empty)
        assert disclosure[1] == "can_be_redacted"  # value
        assert disclosure[2] == "custom_claim"  # key

        # Test hash algorithm consistency (SHA-256)
        from sd_cwt.redaction import hash_disclosure

        computed_hash = hash_disclosure(disclosures[0])
        assert len(computed_hash) == 32  # SHA-256 = 32 bytes

        simple_59 = cbor_utils.create_simple_value(59)
        stored_hashes = decoded[simple_59]
        assert computed_hash in stored_hashes
