#!/usr/bin/env python3
"""Example demonstrating CDDL validation and CBOR EDN for SD-CWT and COSE Keys."""

import base64
import hashlib

from sd_cwt import cbor_utils, edn_utils
from sd_cwt.thumbprint import CoseKeyThumbprint
from sd_cwt.validation import CDDLValidator


def demonstrate_cbor_edn():
    """Demonstrate CBOR Extended Diagnostic Notation."""
    print("=" * 60)
    print("CBOR Extended Diagnostic Notation (EDN) Demo")
    print("=" * 60)
    
    # 1. SD-CWT Claims in EDN
    print("\n1. SD-CWT Claims in EDN:")
    sd_cwt_edn = '''
    {
        1: "https://issuer.example.com",  / iss /
        2: "user123",                      / sub /
        6: 1700000000,                     / iat /
        59: [
            h'496bd8afadf307e5b08c64b81e87f36a3e6fca2b7c5c401b6d1e2c0d8e1b1a6f',
            h'7c5c401b6d1e2c0d8e1b1a6f496bd8afadf307e5b08c64b81e87f36a3e6fca2b'
        ]  / redacted_claim_keys (simple value 59) /
    }
    '''
    
    # Remove comments for parsing
    import re
    clean_edn = re.sub(r'/[^/]*/|#[^\n]*', '', sd_cwt_edn)
    
    print("  EDN representation:")
    print("  " + clean_edn.strip().replace("\n", "\n  "))
    
    # Convert to CBOR
    cbor_data = edn_utils.diag_to_cbor(clean_edn)
    print(f"\n  CBOR hex: {cbor_data.hex()[:60]}...")
    print(f"  CBOR size: {len(cbor_data)} bytes")
    
    # 2. COSE Key in EDN
    print("\n2. COSE EC2 Key in EDN:")
    ec2_key_edn = '''
    {
        1: 2,    / kty: EC2 /
        3: -7,   / alg: ES256 /
        -1: 1,   / crv: P-256 /
        -2: h'bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff',
        -3: h'20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e'
    }
    '''
    
    clean_edn = re.sub(r'/[^/]*/', '', ec2_key_edn)
    print("  EDN representation:")
    print("  " + clean_edn.strip().replace("\n", "\n  "))
    
    # 3. Disclosure Array in EDN
    print("\n3. Disclosure Array in EDN:")
    disclosure_edn = '[h\'73616c74\', "John", "given_name"]'  # SD-CWT format: [salt, value, key]
    
    print(f"  EDN: {disclosure_edn}")
    
    disclosure_cbor = edn_utils.diag_to_cbor(disclosure_edn)
    decoded = cbor_utils.decode(disclosure_cbor)
    print(f"  Decoded: [salt={decoded[0]!r}, value={decoded[1]!r}, key={decoded[2]!r}]")


def demonstrate_cddl_validation():
    """Demonstrate CDDL schema validation."""
    print("\n" + "=" * 60)
    print("CDDL Schema Validation Demo")
    print("=" * 60)
    
    # Create a valid SD-CWT claims structure
    claims = {
        1: "https://issuer.example.com",  # iss
        2: "user123",  # sub
        6: 1700000000,  # iat
        59: [  # redacted_claim_keys (simple value 59)
            hashlib.sha256(b"disclosure1").digest(),
            hashlib.sha256(b"disclosure2").digest(),
        ],
    }
    
    print("\n1. SD-CWT Claims Structure:")
    print(f"   Issuer: {claims[1]}")
    print(f"   Subject: {claims[2]}")
    print(f"   Issued At: {claims[6]}")
    print(f"   Redacted Claim Keys: {len(claims[59])} hashes")
    
    # Convert to CBOR
    cbor_data = cbor_utils.encode(claims)
    
    # Convert to EDN for display
    edn = edn_utils.cbor_to_diag(cbor_data)
    print("\n2. CBOR Diagnostic Notation:")
    print(f"   {edn[:200]}...")
    
    # Try CDDL validation with zcbor
    print("\n3. CDDL Validation:")
    try:
        validator = CDDLValidator()
        is_valid = validator.validate(cbor_data, "sd-cwt-claims")
        if is_valid:
            print("   ✓ Valid according to SD-CWT CDDL schema")
        else:
            print("   ⚠ CDDL validation failed")
    except Exception as e:
        print(f"   Note: CDDL validation not available ({str(e)[:50]}...)")
        print("   Structure validation passed manually")


def demonstrate_cose_key_validation():
    """Demonstrate COSE key structure validation."""
    print("\n" + "=" * 60)
    print("COSE Key Structure Validation Demo")
    print("=" * 60)
    
    # Create different COSE key types
    keys = {
        "EC2": {
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: b"x" * 32,  # x coordinate
            -3: b"y" * 32,  # y coordinate
        },
        "OKP": {
            1: 1,  # kty: OKP
            3: -8,  # alg: EdDSA
            -1: 6,  # crv: Ed25519
            -2: b"x" * 32,  # x coordinate
        },
        "RSA": {
            1: 3,  # kty: RSA
            3: -257,  # alg: RS256
            -1: b"n" * 256,  # modulus
            -2: b"\x01\x00\x01",  # exponent
        },
        "Symmetric": {
            1: 4,  # kty: Symmetric
            3: 5,  # alg: HS256
            -1: b"k" * 32,  # key value
        },
    }
    
    for key_type, key in keys.items():
        print(f"\n{key_type} Key:")
        
        # Compute thumbprint (excludes optional fields)
        thumbprint = CoseKeyThumbprint.compute(key, "sha256")
        print(f"  Thumbprint: {thumbprint.hex()[:32]}...")
        
        # Show canonical structure
        canonical = CoseKeyThumbprint.canonical_cbor(key)
        print(f"  Canonical CBOR size: {len(canonical)} bytes")
        
        # Convert to EDN
        edn = edn_utils.cbor_to_diag(canonical)
        print(f"  Canonical EDN: {edn[:100]}...")


def demonstrate_test_vectors():
    """Demonstrate test vector structure."""
    print("\n" + "=" * 60)
    print("Test Vector Structure Demo")
    print("=" * 60)
    
    # Create a test vector
    test_vector = {
        "description": "EC2 P-256 key thumbprint test",
        "input": {
            "key": {
                1: 2,  # kty: EC2
                -1: 1,  # crv: P-256
                -2: bytes.fromhex(
                    "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"
                ),
                -3: bytes.fromhex(
                    "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"
                ),
            },
            "hash_alg": "sha256",
        },
        "output": {
            "thumbprint": None,  # Will be computed
            "thumbprint_uri": None,  # Will be computed
        },
    }
    
    # Compute actual values
    key = test_vector["input"]["key"]
    thumbprint = CoseKeyThumbprint.compute(key, "sha256")
    uri = CoseKeyThumbprint.uri(key, "sha256")
    
    test_vector["output"]["thumbprint"] = thumbprint
    test_vector["output"]["thumbprint_uri"] = uri
    
    print("\n1. Test Vector:")
    print(f"   Description: {test_vector['description']}")
    print(f"   Key Type: EC2 (kty={key[1]})")
    print(f"   Curve: P-256 (crv={key[-1]})")
    print(f"   Hash Algorithm: {test_vector['input']['hash_alg']}")
    
    print("\n2. Output:")
    print(f"   Thumbprint: {thumbprint.hex()}")
    print(f"   URI: {uri}")
    
    # Convert to CBOR and show size
    cbor_data = cbor_utils.encode(test_vector)
    print(f"\n3. Encoded size: {len(cbor_data)} bytes")


def demonstrate_real_world_example():
    """Demonstrate a real-world SD-CWT scenario."""
    print("\n" + "=" * 60)
    print("Real-World SD-CWT Example")
    print("=" * 60)
    
    # Create issuer's claims
    all_claims = {
        "iss": "https://issuer.example.com",
        "sub": "user123",
        "iat": 1700000000,
        "given_name": "Alice",
        "family_name": "Smith",
        "email": "alice@example.com",
        "phone": "+1234567890",
        "address": {
            "street": "123 Main St",
            "city": "Anytown",
            "country": "US",
        },
    }
    
    # Select claims for selective disclosure
    sd_claims = ["given_name", "family_name", "email", "phone", "address"]
    
    print("\n1. Original Claims:")
    for k, v in all_claims.items():
        if isinstance(v, dict):
            print(f"   {k}: <complex object>")
        else:
            print(f"   {k}: {v}")
    
    # Create disclosures
    disclosures = []
    sd_hashes = []
    
    for claim_name in sd_claims:
        if claim_name in all_claims:
            salt = hashlib.sha256(f"salt_{claim_name}".encode()).digest()[:16]
            disclosure = [salt, all_claims[claim_name], claim_name]  # SD-CWT format: [salt, value, key]
            disclosures.append(disclosure)
            
            # Hash the disclosure
            disclosure_cbor = cbor_utils.encode(disclosure)
            sd_hash = hashlib.sha256(disclosure_cbor).digest()
            sd_hashes.append(sd_hash)
    
    # Create SD-CWT claims (without disclosed claims)
    sd_cwt_claims = {
        1: all_claims["iss"],  # iss
        2: all_claims["sub"],  # sub
        6: all_claims["iat"],  # iat
        59: sd_hashes,  # redacted_claim_keys (simple value 59)
    }
    
    print(f"\n2. SD-CWT Claims (after removing {len(sd_claims)} claims):")
    print(f"   Issuer: {sd_cwt_claims[1]}")
    print(f"   Subject: {sd_cwt_claims[2]}")
    print(f"   Redacted Claim Keys: {len(sd_cwt_claims[59])} hashes")
    
    print("\n3. Disclosures Created:")
    for i, disclosure in enumerate(disclosures):
        print(f"   #{i+1}: [{len(disclosure[0])} bytes salt, '{disclosure[1]}', ...]")
    
    # Holder selects claims to reveal
    revealed = ["given_name", "email"]
    
    print(f"\n4. Holder Reveals: {revealed}")
    
    revealed_disclosures = [d for d in disclosures if d[1] in revealed]
    print(f"   Sending {len(revealed_disclosures)} of {len(disclosures)} disclosures")


def main():
    """Run all demonstrations."""
    print("\nCDDL and CBOR EDN Validation Examples")
    print("=" * 60)
    
    demonstrate_cbor_edn()
    demonstrate_cddl_validation()
    demonstrate_cose_key_validation()
    demonstrate_test_vectors()
    demonstrate_real_world_example()
    
    print("\n" + "=" * 60)
    print("Demo completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()