from sd_cwt import edn_utils
#!/usr/bin/env python3
"""Example script demonstrating CBOR and CDDL validation for SD-CWT."""

import base64
import hashlib
import json

import cbor2

from sd_cwt.validation import CBORValidator, CDDLValidator, SDCWTValidator


def create_sample_sd_cwt():
    """Create a sample SD-CWT for demonstration."""
    # Create disclosure for selective disclosure
    disclosure1 = [b"salt1234567890", "given_name", "Alice"]
    disclosure2 = [b"salt0987654321", "family_name", "Smith"]
    
    # Hash disclosures
    hash1 = base64.urlsafe_b64encode(
        hashlib.sha256(cbor2.dumps(disclosure1)).digest()
    ).rstrip(b"=").decode()
    
    hash2 = base64.urlsafe_b64encode(
        hashlib.sha256(cbor2.dumps(disclosure2)).digest()
    ).rstrip(b"=").decode()
    
    # Create SD-CWT claims
    claims = {
        "iss": "https://issuer.example.com",
        "sub": "user123",
        "iat": 1700000000,
        "email": "alice@example.com",  # Not selectively disclosed
        59: [hash1, hash2]  # redacted_claim_keys (simple value 59)
    }
    
    return cbor2.dumps(claims), [disclosure1, disclosure2]


def demonstrate_cbor_validation():
    """Demonstrate CBOR validation features."""
    print("=" * 60)
    print("CBOR Validation Demo")
    print("=" * 60)
    
    validator = CBORValidator()
    
    # Create sample data
    sample_data = {
        "string": "hello",
        "number": 42,
        "array": [1, 2, 3],
        "nested": {"key": "value"}
    }
    
    cbor_data = cbor2.dumps(sample_data)
    
    # Validate structure
    print("\n1. Validating CBOR structure:")
    is_valid = validator.validate_structure(cbor_data)
    print(f"   Valid: {is_valid}")
    
    # Convert to diagnostic notation
    print("\n2. CBOR Diagnostic notation:")
    diag = validator.to_diagnostic(cbor_data)
    print(f"   {diag}")
    
    # Test invalid CBOR
    print("\n3. Testing invalid CBOR:")
    invalid_cbor = b"not valid cbor"
    is_valid = validator.validate_structure(invalid_cbor)
    print(f"   Valid: {is_valid}")


def demonstrate_sd_cwt_validation():
    """Demonstrate SD-CWT specific validation."""
    print("\n" + "=" * 60)
    print("SD-CWT Validation Demo")
    print("=" * 60)
    
    validator = SDCWTValidator()
    
    # Create sample SD-CWT
    token, disclosures = create_sample_sd_cwt()
    
    print("\n1. Validating SD-CWT token:")
    results = validator.validate_token(token)
    print(f"   Overall valid: {results['valid']}")
    print(f"   CBOR valid: {results['cbor_valid']}")
    print(f"   Has redacted claims: {results['has_redacted_claims']}")
    print(f"   Has sd_alg header: {results['has_sd_alg_header']}")
    if results['errors']:
        print(f"   Errors: {results['errors']}")
    
    print("\n2. Token diagnostic notation:")
    validator.print_diagnostic(token)
    
    print("\n3. Validating disclosures:")
    for i, disclosure in enumerate(disclosures, 1):
        disclosure_cbor = cbor2.dumps(disclosure)
        results = validator.validate_disclosure(disclosure_cbor)
        print(f"   Disclosure {i}: Valid={results['valid']}")
        if not results['valid']:
            print(f"     Errors: {results['errors']}")


def demonstrate_cbor_diag():
    """Demonstrate cbor-diag features."""
    print("\n" + "=" * 60)
    print("CBOR Diagnostic Notation Demo")
    print("=" * 60)
    
    # Create complex CBOR structure
    complex_data = {
        1: "issuer",  # Using integer keys like in CWT
        2: "subject",
        6: 1700000000,
        59: [  # redacted_claim_keys (simple value 59)
            base64.b64decode("aGFzaDEK"),  # Binary data
            base64.b64decode("aGFzaDIK"),
        ],
        "nested": {
            "array": [1, 2, {"key": "value"}],
            "binary": b"\x01\x02\x03\x04"
        }
    }
    
    cbor_data = cbor2.dumps(complex_data)
    
    print("\n1. Original Python data:")
    # Convert to JSON-serializable format
    json_safe = {}
    for k, v in complex_data.items():
        if isinstance(v, bytes):
            json_safe[k] = '<binary>'
        elif isinstance(v, dict):
            json_safe[k] = {kk: '<binary>' if isinstance(vv, bytes) else vv for kk, vv in v.items()}
        elif isinstance(v, list):
            json_safe[k] = ['<binary>' if isinstance(item, bytes) else item for item in v]
        else:
            json_safe[k] = v
    print(f"   {json.dumps(json_safe, indent=2)}")
    
    print("\n2. CBOR hex representation:")
    print(f"   {cbor_data.hex()}")
    
    print("\n3. CBOR diagnostic notation:")
    diag = edn_utils.cbor_to_diag(cbor_data)
    print(f"   {diag}")
    
    print("\n4. Round-trip test:")
    cbor_from_diag = edn_utils.diag_to_cbor(diag)
    round_trip_data = cbor2.loads(cbor_from_diag)
    print(f"   Round-trip successful: {round_trip_data == complex_data}")


def main():
    """Run all demonstrations."""
    print("\nSD-CWT CBOR/CDDL Validation Examples")
    print("=" * 60)
    
    demonstrate_cbor_validation()
    demonstrate_sd_cwt_validation()
    demonstrate_cbor_diag()
    
    print("\n" + "=" * 60)
    print("Demo completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()