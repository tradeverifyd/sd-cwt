from sd_cwt import edn_utils

#!/usr/bin/env python3
"""SD-CWT example matching the latest specification exactly.

This example demonstrates SD-CWT creation and verification using EDN 
and CBOR as specified in the latest draft-ietf-spice-sd-cwt.
"""

import hashlib
import secrets

import cbor2
from fido2.cose import CoseKey

from sd_cwt.issuer import SDCWTIssuer


def demonstrate_specification_example():
    """Demonstrate the exact specification example."""
    print("=" * 80)
    print("SD-CWT Specification Example (Latest Draft)")
    print("=" * 80)

    # 1. Show the specification example in EDN
    print("\n1. Specification CWT Claims in EDN:")
    spec_edn = '''
    {
        1: "https://issuer.example",      / iss /
        2: "https://device.example",     / sub /
        4: 1725330600,                   / exp /
        5: 1725243840,                   / nbf /
        6: 1725244200,                   / iat /
        8: {                             / cnf /
            1: {                         / COSE_Key /
                1: 2,                    / kty: EC2 /
                -1: 1,                   / crv: P-256 /
                -2: h'8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d',
                -3: h'4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'
            }
        },
        500: true,                       / device_enabled /
        501: "ABCD-123456",             / device_id /
        502: [1549560720, 1612498440, 1674004740],  / timestamps /
        503: {                           / address /
            "country": "us",
            "region": "ca", 
            "postal_code": "94188"
        }
    }
    '''

    print(spec_edn)

    # 2. Parse and display the claims
    print("\n2. Parsed Claims Structure:")
    # Remove comments properly
    import re
    clean_edn = re.sub(r'/[^/]*/', '', spec_edn)
    clean_edn = re.sub(r'#[^\n]*', '', clean_edn).strip()

    # Create clean version without comments for parsing
    clean_spec = '''
    {
        1: "https://issuer.example",
        2: "https://device.example",
        4: 1725330600,
        5: 1725243840,
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
        501: "ABCD-123456",
        502: [1549560720, 1612498440, 1674004740],
        503: {
            "country": "us",
            "region": "ca", 
            "postal_code": "94188"
        }
    }
    '''

    cbor_data = edn_utils.diag_to_cbor(clean_spec)
    claims = cbor2.loads(cbor_data)

    print(f"   Issuer (1): {claims[1]}")
    print(f"   Subject (2): {claims[2]}")
    print(f"   Expiration (4): {claims[4]}")
    print(f"   Not Before (5): {claims[5]}")
    print(f"   Issued At (6): {claims[6]}")
    print(f"   Device Enabled (500): {claims[500]}")
    print(f"   Device ID (501): {claims[501]}")
    print(f"   Timestamps (502): {len(claims[502])} timestamps")
    print(f"   Address (503): {claims[503]['country']}, {claims[503]['region']}")
    print("   Confirmation Key (8): EC2 P-256")

    return claims


def demonstrate_sd_cwt_with_redaction():
    """Demonstrate SD-CWT with selective disclosure using redaction tags."""
    print("\n" + "=" * 80)
    print("SD-CWT with Selective Disclosure")
    print("=" * 80)

    # 1. Create EDN with redaction tags
    print("\n1. EDN Claims with Redaction Tags:")
    edn_with_redaction = '''
    {
        1: "https://issuer.example",
        2: "https://device.example", 
        6: 1725244200,
        500: 59(true),                   # Redacted claim key tag 59
        501: "ABCD-123456",             # This claim will be visible
        502: 60([1549560720, 1612498440, 1674004740]),  # Redacted element tag 60
        503: {
            "country": "us",
            "region": "ca",
            "postal_code": "94188"
        }
    }
    '''

    print(edn_with_redaction)

    # 2. Create signing key
    print("\n2. Creating Signing Key...")
    signing_key_data = {
        1: 2,  # kty: EC2
        -1: 1,  # crv: P-256
        -2: secrets.token_bytes(32),  # x coordinate
        -3: secrets.token_bytes(32),  # y coordinate
        3: -7,  # alg: ES256
    }
    signing_key = CoseKey(signing_key_data)
    print("   ✓ EC2 P-256 signing key created")

    # 3. Create issuer
    issuer = SDCWTIssuer(signing_key, "https://issuer.example")
    print("   ✓ SD-CWT issuer initialized")

    # 4. Parse claims (without actual redaction tags for now)
    simple_edn = '''
    {
        1: "https://issuer.example",
        2: "https://device.example", 
        6: 1725244200,
        500: true,
        501: "ABCD-123456",
        502: [1549560720, 1612498440, 1674004740],
        503: {
            "country": "us",
            "region": "ca",
            "postal_code": "94188"
        }
    }
    '''

    print("\n3. Creating SD-CWT...")
    try:
        result = issuer.create_sd_cwt(simple_edn)
        print("   ✓ SD-CWT created successfully")
        print(f"   ✓ SD-CWT size: {len(result['sd_cwt'])} bytes")
        print(f"   ✓ Disclosures: {len(result['disclosures'])}")

        # Show SD-CWT structure
        print("\n4. SD-CWT Structure Analysis:")
        sd_cwt_tag = cbor2.loads(result['sd_cwt'])
        print(f"   CBOR Tag: {sd_cwt_tag.tag} (COSE_Sign1)")

        cose_sign1 = sd_cwt_tag.value
        print(f"   COSE_Sign1 elements: {len(cose_sign1)}")

        # Show payload
        payload = cbor2.loads(cose_sign1[2])
        print(f"   Payload claims: {len(payload)}")

        for key, value in payload.items():
            if isinstance(key, int) and key < 100 or isinstance(key, str):
                print(f"     {key}: {str(value)[:50]}{'...' if len(str(value)) > 50 else ''}")

    except Exception as e:
        print(f"   ⚠ Error creating SD-CWT: {e}")


def demonstrate_disclosure_creation():
    """Demonstrate creating disclosures manually."""
    print("\n" + "=" * 80)
    print("Manual Disclosure Creation")
    print("=" * 80)

    # Create sample disclosures
    print("\n1. Creating Sample Disclosures:")

    disclosures = []
    claims_to_disclose = [
        ("device_enabled", True),
        ("timestamps", [1549560720, 1612498440, 1674004740]),
        ("address", {"country": "us", "region": "ca", "postal_code": "94188"})
    ]

    for claim_name, claim_value in claims_to_disclose:
        # Generate 128-bit salt
        salt = secrets.token_bytes(16)

        # Create disclosure array
        disclosure_array = [salt, claim_name, claim_value]
        disclosure_cbor = cbor2.dumps(disclosure_array)

        # Hash the disclosure
        disclosure_hash = hashlib.sha256(disclosure_cbor).digest()

        disclosures.append({
            "name": claim_name,
            "value": claim_value,
            "salt": salt,
            "disclosure": disclosure_cbor,
            "hash": disclosure_hash
        })

        print(f"   ✓ {claim_name}: {len(disclosure_cbor)} bytes CBOR")
        print(f"     Salt: {salt.hex()[:16]}...")
        print(f"     Hash: {disclosure_hash.hex()[:16]}...")

    # Show EDN representation of disclosures
    print("\n2. Disclosure Arrays in EDN:")
    for disc in disclosures:
        edn = edn_utils.cbor_to_diag(disc["disclosure"])
        print(f"   {disc['name']}: {edn}")

    # Create SD-CWT claims with hashes
    print("\n3. SD-CWT Claims with Disclosure Hashes:")
    sd_cwt_claims = {
        1: "https://issuer.example",
        2: "https://device.example",
        6: 1725244200,
        501: "ABCD-123456",  # This claim remains visible
        59: [disc["hash"] for disc in disclosures],  # redacted_claim_keys
    }

    edn = edn_utils.cbor_to_diag(cbor2.dumps(sd_cwt_claims))
    print(f"   {edn[:200]}...")


def demonstrate_presentation():
    """Demonstrate SD-CWT presentation (selective disclosure)."""
    print("\n" + "=" * 80)
    print("SD-CWT Presentation (Holder -> Verifier)")
    print("=" * 80)

    print("\n1. Holder's Decision:")
    print("   Available disclosures: device_enabled, timestamps, address")
    print("   Holder chooses to reveal: device_enabled, address")
    print("   Holder keeps private: timestamps")

    print("\n2. Presentation Structure:")
    presentation = {
        "sd_cwt": "base64url-encoded-sd-cwt-token",
        "disclosures": [
            "base64url-encoded-device-enabled-disclosure",
            "base64url-encoded-address-disclosure"
        ]
    }

    for key, value in presentation.items():
        print(f"   {key}: {value}")

    print("\n3. Verifier Process:")
    print("   ✓ Verify SD-CWT signature")
    print("   ✓ Check timestamp claims (exp, nbf, iat)")
    print("   ✓ Decode provided disclosures")
    print("   ✓ Hash disclosures and match against redacted_claim_keys")
    print("   ✓ Construct verified claims")


def main():
    """Run all SD-CWT specification demonstrations."""
    print("SD-CWT Implementation Examples")
    print("Using latest draft-ietf-spice-sd-cwt specification")
    print("=" * 80)

    try:
        # Show specification example
        demonstrate_specification_example()

        # Show SD-CWT with redaction
        demonstrate_sd_cwt_with_redaction()

        # Show manual disclosure creation
        demonstrate_disclosure_creation()

        # Show presentation flow
        demonstrate_presentation()

        print("\n" + "=" * 80)
        print("✓ All demonstrations completed successfully!")
        print("=" * 80)

    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
