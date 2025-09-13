"""Test the simple API workflow from annotation to presentation verification."""

import pytest

from sd_cwt import (
    SDCWTIssuer,
    SDCWTPresenter,
    SDCWTVerifier,
    cbor_utils,
    cose_key_generate,
    cose_key_kid_resolver,
    create_edn_with_annotations,
    create_presentation_edn,
)
from sd_cwt.thumbprint import CoseKeyThumbprint


class TestSimpleAPIWorkflow:
    """Test the complete SD-CWT workflow using simple APIs."""

    def test_complete_workflow_guide_example(self):
        """Test the complete workflow based on the guide.md example."""
        # Step 1: Generate keys (issuer and holder)
        issuer_private_key_cbor = cose_key_generate()
        holder_private_key_cbor = cose_key_generate()

        issuer_key_dict = cbor_utils.decode(issuer_private_key_cbor)
        holder_key_dict = cbor_utils.decode(holder_private_key_cbor)

        # Extract public key for holder
        holder_public_key = cbor_utils.decode(holder_private_key_cbor)
        # Remove private key component to make it public
        if -4 in holder_public_key:
            del holder_public_key[-4]
        holder_public_key_cbor = cbor_utils.encode(holder_public_key)

        print("✓ Generated issuer and holder keys")

        # Step 2: Define claims (from guide.md example)
        base_claims = {
            "production_date": "2024-01-15",
            "steel_grade": "ASTM A615 Grade 60",
        }

        optional_claims = {
            "heat_number": "H240115-001",
            "chemical_composition": {
                "carbon": 0.25,
                "manganese": 1.20,
                "phosphorus": 0.040,
                "sulfur": 0.050
            },
            "production_cost": 850.75,
            "quality_test_results": {
                "tensile_strength": 420,
                "yield_strength": 350,
                "elongation": 18.5
            }
        }

        print("✓ Defined mandatory and optional claims")

        # Step 3: Issue credential with selective disclosure
        issuer = SDCWTIssuer(issuer_key_dict)

        sd_cwt, edn_string, disclosures = issuer.issue_credential(
            base_claims=base_claims,
            optional_claims=optional_claims,
            holder_public_key=holder_public_key_cbor,
            issuer="https://steel-manufacturer.example",
            subject="https://customs-broker.example"
        )

        assert isinstance(sd_cwt, bytes), "SD-CWT should be bytes"
        assert isinstance(edn_string, str), "EDN should be string"
        assert isinstance(disclosures, list), "Disclosures should be list"

        print("✓ Issued SD-CWT credential with selective disclosure")
        print(f"  - Disclosures created: {len(disclosures)}")

        # Step 4: Create presentation selecting specific claims
        presenter = SDCWTPresenter(holder_key_dict)

        # Select subset of optional claims to disclose
        selected_claims = ["heat_number", "chemical_composition"]

        # For simplicity in this test, we'll select some disclosures
        # In a real implementation, the presenter would match disclosures to claim names
        selected_disclosures = disclosures[:2] if len(disclosures) >= 2 else disclosures

        kbt = presenter.create_presentation(
            sd_cwt=sd_cwt,
            disclosures=disclosures,
            selected_disclosures=selected_disclosures,
            audience="https://customs.us.example",
            nonce="1234567890"
        )

        assert isinstance(kbt, bytes), "KBT should be bytes"

        print("✓ Created presentation with selected disclosures")

        # Step 5: Set up verification
        # Create issuer key resolver
        issuer_thumbprint = CoseKeyThumbprint.compute(issuer_key_dict, "sha256")
        issuer_kid_pairs = [(issuer_thumbprint, issuer_private_key_cbor)]
        issuer_resolver = cose_key_kid_resolver(issuer_kid_pairs)

        verifier = SDCWTVerifier(issuer_resolver)

        print("✓ Set up verifier with issuer key resolver")

        # Step 6: Verify presentation
        is_valid, verified_claims, tags_absent = verifier.verify_presentation(
            kbt=kbt,
            expected_audience="https://customs.us.example"
        )

        assert is_valid, "Presentation should be cryptographically valid"
        assert verified_claims is not None, "Should extract verified claims"
        assert tags_absent, "Redaction tags (58, 59, 60) should be absent from final claims"

        print("✓ Verified presentation successfully")
        print("✓ Confirmed no redaction tags in final claims")

        # Step 7: Check that mandatory claims are present
        assert "iss" in verified_claims
        assert "sub" in verified_claims
        assert "iat" in verified_claims
        assert verified_claims["iss"] == "https://steel-manufacturer.example"
        assert verified_claims["sub"] == "https://customs-broker.example"

        print("✓ Mandatory claims present and correct")

        # Step 8: Check that base claims (mandatory to disclose) are present
        for claim_name in base_claims.keys():
            assert claim_name in verified_claims, f"Base claim {claim_name} should be present"
            assert verified_claims[claim_name] == base_claims[claim_name], f"Base claim {claim_name} should match"

        print("✓ Base claims (mandatory to disclose) present and correct")

        print("✓ Complete workflow test passed!")

    def test_edn_annotation_workflow(self):
        """Test EDN annotation and presentation workflow."""
        # Generate keys
        holder_key_cbor = cose_key_generate()
        holder_key_dict = cbor_utils.decode(holder_key_cbor)

        # Extract public key
        holder_public_key = holder_key_dict.copy()
        if -4 in holder_public_key:
            del holder_public_key[-4]
        holder_public_key_cbor = cbor_utils.encode(holder_public_key)

        # Create EDN with annotations
        base_claims = {"production_date": "2024-01-15"}
        optional_claims = {"heat_number": "H240115-001", "cost": 850.75}

        edn = create_edn_with_annotations(
            base_claims=base_claims,
            optional_claims=optional_claims,
            holder_public_key=holder_public_key_cbor
        )

        assert isinstance(edn, str), "EDN should be string"
        assert "58(" in edn, "EDN should contain tag 58 for optional claims"
        assert '"production_date": "2024-01-15"' in edn, "Base claims should not have tags"
        assert '"heat_number": 58("H240115-001")' in edn, "Optional claims should have tag 58"

        print("✓ EDN annotation workflow test passed")

    def test_presentation_edn_cleaning(self):
        """Test EDN cleaning for presentations."""
        original_edn = '''
{
  1: "https://issuer.example",
  2: "https://subject.example",
  6: 1725244200,
  8: { 1: { 1: 2, -1: 1, -2: h'abc123', -3: h'def456' } },
  "production_date": "2024-01-15",
  "heat_number": 58("H240115-001"),
  "cost": 58(850.75)
}
        '''.strip()

        selected_claims = ["heat_number"]

        presentation_edn = create_presentation_edn(original_edn, selected_claims)

        assert isinstance(presentation_edn, str), "Presentation EDN should be string"
        assert '"heat_number": "H240115-001"' in presentation_edn, "Selected claims should be clean"
        assert "58(" not in presentation_edn or presentation_edn.count("58(") < original_edn.count("58("), \
            "Tag 58 should be removed from selected claims"

        print("✓ Presentation EDN cleaning test passed")

    def test_tag_absence_verification(self):
        """Test that verifier correctly detects absence of redaction tags."""
        # This is a simplified test to verify the tag detection logic
        from sd_cwt.simple_api import SDCWTVerifier
        import sd_cwt.cbor_utils as cbor_utils

        # Create a mock verifier to test tag detection
        mock_resolver = lambda kid: {"mock": "key"}
        verifier = SDCWTVerifier(mock_resolver)

        # Test payload with no redaction tags (clean)
        clean_payload = {
            1: "issuer",
            2: "subject",
            6: 1725244200,
            8: {"cnf": "data"},
            "production_date": "2024-01-15",
            "heat_number": "H240115-001"
        }

        clean_claims, tags_absent = verifier._extract_clean_claims(clean_payload)
        assert tags_absent, "Clean payload should have tags_absent=True"
        assert "production_date" in clean_claims
        assert "heat_number" in clean_claims

        print("✓ Tag absence verification test passed")

    def test_error_handling(self):
        """Test error handling in the workflow."""
        # Test with invalid KBT
        from sd_cwt.simple_api import SDCWTVerifier

        mock_resolver = lambda kid: {"mock": "key"}
        verifier = SDCWTVerifier(mock_resolver)

        # Invalid KBT should return False
        is_valid, claims, tags_absent = verifier.verify_presentation(
            kbt=b"invalid_kbt",
            expected_audience="https://test.example"
        )

        assert not is_valid, "Invalid KBT should not verify"
        assert claims is None, "Invalid KBT should return None claims"
        assert not tags_absent, "Invalid KBT should return tags_absent=False"

        print("✓ Error handling test passed")

    def test_workflow_with_complex_claims(self):
        """Test workflow with complex nested claims."""
        # Generate keys
        issuer_key_cbor = cose_key_generate()
        holder_key_cbor = cose_key_generate()

        issuer_key_dict = cbor_utils.decode(issuer_key_cbor)
        holder_key_dict = cbor_utils.decode(holder_key_cbor)

        # Extract public key
        holder_public_key = holder_key_dict.copy()
        if -4 in holder_public_key:
            del holder_public_key[-4]
        holder_public_key_cbor = cbor_utils.encode(holder_public_key)

        # Complex claims with nested structures
        base_claims = {
            "document_type": "steel_certificate",
            "issuer_info": {
                "name": "Steel Manufacturing Corp",
                "license": "SMC-2024-001"
            }
        }

        optional_claims = {
            "detailed_composition": {
                "elements": {
                    "carbon": 0.25,
                    "manganese": 1.20,
                    "silicon": 0.30
                },
                "additives": ["chromium", "nickel"]
            },
            "test_results": [420, 350, 18.5],
            "confidential_notes": "Internal batch notes here"
        }

        # Test issuance
        issuer = SDCWTIssuer(issuer_key_dict)
        sd_cwt, edn, disclosures = issuer.issue_credential(
            base_claims=base_claims,
            optional_claims=optional_claims,
            holder_public_key=holder_public_key_cbor
        )

        # Test presentation
        presenter = SDCWTPresenter(holder_key_dict)
        kbt = presenter.create_presentation(
            sd_cwt=sd_cwt,
            disclosures=disclosures,
            selected_disclosures=disclosures[:1],  # Select one disclosure
            audience="https://verifier.example"
        )

        # Test verification
        issuer_thumbprint = CoseKeyThumbprint.compute(issuer_key_dict, "sha256")
        issuer_resolver = cose_key_kid_resolver([(issuer_thumbprint, issuer_key_cbor)])
        verifier = SDCWTVerifier(issuer_resolver)

        is_valid, claims, tags_absent = verifier.verify_presentation(
            kbt=kbt,
            expected_audience="https://verifier.example"
        )

        assert is_valid, "Complex claims presentation should verify"
        assert tags_absent, "Complex claims should not have redaction tags in final result"

        # Check nested claims
        assert "document_type" in claims
        assert "issuer_info" in claims
        assert isinstance(claims["issuer_info"], dict)

        print("✓ Complex claims workflow test passed")