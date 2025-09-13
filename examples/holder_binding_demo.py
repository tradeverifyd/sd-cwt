#!/usr/bin/env python3
"""Demo script showing mandatory holder binding in SD-CWT."""

import time
import cbor2
from sd_cwt import (
    cose_key_generate,
    cose_key_to_dict,
    create_sd_cwt_with_holder_binding,
    create_sd_cwt_presentation,
    validate_sd_cwt_presentation,
    SeededSaltGenerator,
)
from sd_cwt.cose_sign1 import ES256Signer


def demonstrate_mandatory_holder_binding():
    """Show that holder binding (cnf claim) is always mandatory."""
    print("=" * 60)
    print("MANDATORY HOLDER BINDING DEMONSTRATION")
    print("=" * 60)

    print("\nAccording to the SD-CWT specification:")
    print("• Holder binding is REQUIRED (not optional)")
    print("• Every SD-CWT MUST contain a cnf (confirmation) claim")
    print("• Every presentation MUST be signed by the holder's key")
    print("• The cnf claim binds the credential to the holder")

    # Generate issuer key
    print("\n1. Setting up issuer...")
    issuer_key = cose_key_generate(key_id=b"dmv-issuer-2024")
    issuer_dict = cose_key_to_dict(issuer_key)
    issuer_signer = ES256Signer(issuer_dict[-4])
    print("   ✓ Issuer key generated with ID")

    # EDN claims for driver's license
    edn_claims = """
    {
        1: "https://dmv.example.gov",
        2: "license-987654321",
        4: 1756656000,
        6: 1725244200,

        "license_class": "Class C",
        "issued_state": "California",
        "restrictions": "NONE",

        "full_name": 59("Jane Smith"),
        "date_of_birth": 59("1995-03-20"),
        "height": 59("5'6"),
        "eye_color": 59("Brown"),

        "license_number": 59("CA123456789"),
        "address": 59({
            "street": "456 Oak Avenue",
            "city": "Los Angeles",
            "state": "CA",
            "zip": "90210"
        })
    }
    """

    print("\n2. Creating SD-CWT with mandatory holder binding...")

    # Deterministic for demo purposes
    seeded_gen = SeededSaltGenerator(seed=0x12345)

    # This function ALWAYS includes cnf claim - holder binding is mandatory
    sd_cwt_result = create_sd_cwt_with_holder_binding(
        edn_claims,
        issuer_signer,
        salt_generator=seeded_gen,
        issuer_key_id=b"dmv-issuer-2024"
    )

    print(f"   ✓ SD-CWT created: {len(sd_cwt_result['sd_cwt'])} bytes")
    print(f"   ✓ Holder key generated: {len(sd_cwt_result['holder_key'])} bytes")
    print(f"   ✓ Disclosures created: {len(sd_cwt_result['disclosures'])}")

    # Verify cnf claim is present
    sd_cwt = sd_cwt_result["sd_cwt"]
    decoded = cbor2.loads(sd_cwt)
    payload = cbor2.loads(decoded.value[2])

    if 8 in payload:
        print("   ✓ MANDATORY cnf claim is present")
        cnf_claim = payload[8]
        if 1 in cnf_claim:
            print("   ✓ Full COSE_Key included in cnf claim")
        elif 3 in cnf_claim:
            print("   ✓ COSE Key Thumbprint included in cnf claim")
    else:
        print("   ✗ ERROR: cnf claim missing (specification violation!)")

    return sd_cwt_result


def demonstrate_holder_presentation():
    """Show holder creating a presentation with selected disclosures."""
    print("\n" + "=" * 60)
    print("HOLDER PRESENTATION DEMONSTRATION")
    print("=" * 60)

    # Get SD-CWT from previous demo
    sd_cwt_result = demonstrate_mandatory_holder_binding()

    print("\n3. Holder creating presentation for verifier...")

    # Setup holder signer (holder controls this key)
    holder_key_dict = cose_key_to_dict(sd_cwt_result["holder_key"])
    holder_signer = ES256Signer(holder_key_dict[-4])

    # Holder selects which disclosures to reveal
    # For age verification, might only reveal name and date of birth
    selected_disclosures = [0, 1]  # name and date_of_birth

    # Presentation parameters
    verifier_audience = "https://age-verifier.example.com"
    presentation_time = int(time.time())
    challenge_nonce = b"verify_age_challenge_2024"

    print(f"   • Target audience: {verifier_audience}")
    print(f"   • Challenge nonce: {challenge_nonce.decode()}")
    print(f"   • Disclosures to reveal: {len(selected_disclosures)} of {len(sd_cwt_result['disclosures'])}")

    # Create presentation (SD-KBT)
    presentation = create_sd_cwt_presentation(
        sd_cwt_result["sd_cwt"],
        sd_cwt_result["disclosures"],
        selected_disclosures,
        holder_signer,
        verifier_audience,
        presentation_time,
        cnonce=challenge_nonce,
        holder_key_id=b"holder-mobile-key"
    )

    print(f"   ✓ SD-KBT presentation created: {len(presentation)} bytes")

    # Show hex for sharing
    presentation_hex = presentation.hex()
    print(f"   ✓ Presentation hex: {presentation_hex[:60]}...")

    return presentation


def demonstrate_verifier_validation():
    """Show verifier validating a holder presentation."""
    print("\n" + "=" * 60)
    print("VERIFIER VALIDATION DEMONSTRATION")
    print("=" * 60)

    # Get presentation from previous demo
    presentation = demonstrate_holder_presentation()

    print("\n4. Verifier validating presentation...")

    # Verifier validates the complete presentation
    validation_result = validate_sd_cwt_presentation(presentation)

    if validation_result["valid"]:
        print("   ✓ Presentation is VALID")
        print(f"   ✓ Audience matches: {validation_result['audience']}")
        print(f"   ✓ Presentation time: {validation_result['issued_at']}")
        print(f"   ✓ Challenge nonce: {validation_result['cnonce'].decode()}")
        print(f"   ✓ Disclosed claims: {len(validation_result['disclosures'])}")

        # Show what was disclosed
        print("\n   Disclosed information:")
        for i, disclosure in enumerate(validation_result["disclosures"]):
            decoded_disclosure = cbor2.loads(disclosure)
            claim_name = decoded_disclosure[2]
            claim_value = decoded_disclosure[1]
            print(f"     • {claim_name}: {claim_value}")

    else:
        print("   ✗ Presentation VALIDATION FAILED")
        for error in validation_result["errors"]:
            print(f"     • Error: {error}")

    return validation_result["valid"]


def demonstrate_security_properties():
    """Show key security properties of the holder binding system."""
    print("\n" + "=" * 60)
    print("SECURITY PROPERTIES DEMONSTRATION")
    print("=" * 60)

    print("\nKey security properties provided by mandatory holder binding:")

    print("\n1. HOLDER AUTHENTICATION:")
    print("   • Holder must possess the private key from cnf claim")
    print("   • Each presentation proves key possession via signature")
    print("   • Prevents credential theft/replay by unauthorized parties")

    print("\n2. PRESENTATION BINDING:")
    print("   • Each SD-KBT is bound to specific verifier (aud claim)")
    print("   • Presentation time prevents replay attacks (iat claim)")
    print("   • Challenge nonce provides additional replay protection")

    print("\n3. DISCLOSURE INTEGRITY:")
    print("   • Selected disclosures are integrity-protected in SD-KBT")
    print("   • Tampering with disclosures invalidates holder signature")
    print("   • Verifier can trust disclosed claim authenticity")

    print("\n4. SPECIFICATION COMPLIANCE:")
    print("   • cnf claim is REQUIRED (not optional) per SD-CWT spec")
    print("   • SD-KBT is REQUIRED for every presentation")
    print("   • iss and sub claims MUST NOT be present in SD-KBT")

    # Generate example with thumbprint
    print("\n5. SIZE OPTIMIZATION:")
    issuer_key = cose_key_generate()
    issuer_dict = cose_key_to_dict(issuer_key)
    issuer_signer = ES256Signer(issuer_dict[-4])

    edn = '{"test": 59("value")}'

    # With full key
    result_full = create_sd_cwt_with_holder_binding(edn, issuer_signer, use_thumbprint=False)

    # With thumbprint
    result_thumb = create_sd_cwt_with_holder_binding(edn, issuer_signer, use_thumbprint=True)

    print(f"   • Full COSE_Key in cnf: {len(result_full['sd_cwt'])} bytes")
    print(f"   • COSE Key Thumbprint: {len(result_thumb['sd_cwt'])} bytes")
    print(f"   • Size reduction: {len(result_full['sd_cwt']) - len(result_thumb['sd_cwt'])} bytes")


def main():
    """Run all holder binding demonstrations."""
    print("SD-CWT MANDATORY HOLDER BINDING DEMONSTRATION")
    print("Based on IETF SPICE SD-CWT specification")

    # Run all demonstrations
    demonstrate_mandatory_holder_binding()
    demonstrate_holder_presentation()
    demonstrate_verifier_validation()
    demonstrate_security_properties()

    print("\n" + "=" * 60)
    print("DEMONSTRATION COMPLETE")
    print("=" * 60)
    print("\nKey takeaways:")
    print("✓ Holder binding (cnf claim) is MANDATORY in SD-CWT")
    print("✓ Every presentation requires an SD-KBT signed by holder")
    print("✓ kid (Key ID) values are included for key identification")
    print("✓ COSE Key Thumbprints can reduce SD-CWT size")
    print("✓ Complete cryptographic binding between issuer, holder, and verifier")


if __name__ == "__main__":
    main()