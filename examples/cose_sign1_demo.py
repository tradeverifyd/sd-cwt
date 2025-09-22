#!/usr/bin/env python3
"""Demo script for COSE Sign1 functionality."""

import json

from sd_cwt import (
    CoseAlgorithm,
    cose_key_generate,
    cose_key_get_public,
    cose_key_to_dict,
    cose_sign1_sign,
    cose_sign1_verify,
)

# Import internal implementations for demo purposes
from sd_cwt.cose_sign1 import (
    ES256Signer,
    ES256Verifier,
)


def demo_basic_sign_verify():
    """Demonstrate basic COSE Sign1 signing and verification."""
    print("=" * 60)
    print("COSE Sign1 Basic Demo")
    print("=" * 60)

    # Generate a COSE key
    print("\n1. Generating ES256 key pair...")
    cose_key = cose_key_generate(CoseAlgorithm.ES256)
    key_dict = cose_key_to_dict(cose_key)

    print(f"   Key type: {key_dict[1]} (EC2)")
    print(f"   Algorithm: {key_dict[3]} (ES256)")
    print(f"   Curve: {key_dict[-1]} (P-256)")

    # Extract key components for signer/verifier
    private_key_bytes = key_dict[-4]  # d parameter
    public_key_x = key_dict[-2]  # x coordinate
    public_key_y = key_dict[-3]  # y coordinate

    # Create signer and verifier
    signer = ES256Signer(private_key_bytes)
    verifier = ES256Verifier(public_key_x, public_key_y)

    # Create a payload
    payload = b"Hello, COSE Sign1!"
    print(f"\n2. Signing payload: {payload.decode()}")

    # Sign the payload
    cose_sign1_message = cose_sign1_sign(payload, signer)
    print(f"   Signed message size: {len(cose_sign1_message)} bytes")

    # Verify the signature
    print("\n3. Verifying signature...")
    is_valid, recovered_payload = cose_sign1_verify(cose_sign1_message, verifier)

    if is_valid:
        print("   ✓ Signature is valid!")
        print(f"   ✓ Recovered payload: {recovered_payload.decode()}")
    else:
        print("   ✗ Signature verification failed!")

    return cose_sign1_message, verifier


def demo_with_headers():
    """Demonstrate COSE Sign1 with custom headers."""
    print("\n" + "=" * 60)
    print("COSE Sign1 with Custom Headers")
    print("=" * 60)

    # Generate key and create signer
    cose_key = cose_key_generate(CoseAlgorithm.ES256)
    key_dict = cose_key_to_dict(cose_key)
    signer = ES256Signer(key_dict[-4])
    verifier = ES256Verifier(key_dict[-2], key_dict[-3])

    # Custom headers
    protected_header = {
        1: -7,  # Algorithm (ES256)
        4: b"demo-key-001",  # Key ID
    }

    unprotected_header = {
        "content-type": "application/json",
        "created": "2024-01-01",
    }

    # JSON payload
    json_payload = json.dumps({
        "message": "Test message",
        "timestamp": "2024-01-01T12:00:00Z"
    }).encode()

    print("\n1. Signing with custom headers:")
    print(f"   Protected: {protected_header}")
    print(f"   Unprotected: {unprotected_header}")
    print(f"   Payload: {json_payload.decode()}")

    # Sign with headers
    cose_sign1_message = cose_sign1_sign(
        json_payload,
        signer,
        protected_header=protected_header,
        unprotected_header=unprotected_header
    )

    print(f"   Signed message size: {len(cose_sign1_message)} bytes")

    # Verify
    print("\n2. Verifying...")
    is_valid, recovered = cose_sign1_verify(cose_sign1_message, verifier)

    if is_valid:
        print("   ✓ Signature is valid!")
        print(f"   ✓ Recovered JSON: {json.loads(recovered)}")
    else:
        print("   ✗ Verification failed!")


def demo_multiple_algorithms():
    """Demonstrate different COSE algorithms."""
    print("\n" + "=" * 60)
    print("Multiple Algorithm Support")
    print("=" * 60)

    algorithms = [
        (CoseAlgorithm.ES256, "ES256 (ECDSA P-256 with SHA-256)"),
        (CoseAlgorithm.ES384, "ES384 (ECDSA P-384 with SHA-384)"),
        (CoseAlgorithm.ES512, "ES512 (ECDSA P-521 with SHA-512)"),
        (CoseAlgorithm.EdDSA, "EdDSA (Ed25519)"),
    ]

    print("\nGenerating keys for different algorithms:")
    for alg, description in algorithms:
        cose_key = cose_key_generate(alg)
        key_dict = cose_key_to_dict(cose_key)

        print(f"\n{description}:")
        print(f"  Key type: {key_dict[1]}")
        print(f"  Algorithm: {key_dict[3]}")
        print(f"  CBOR size: {len(cose_key)} bytes")

        # Get public key only
        public_key = cose_key_get_public(cose_key)
        print(f"  Public key size: {len(public_key)} bytes")


def demo_external_aad():
    """Demonstrate COSE Sign1 with external Additional Authenticated Data."""
    print("\n" + "=" * 60)
    print("COSE Sign1 with External AAD")
    print("=" * 60)

    # Generate key
    cose_key = cose_key_generate()
    key_dict = cose_key_to_dict(cose_key)
    signer = ES256Signer(key_dict[-4])
    verifier = ES256Verifier(key_dict[-2], key_dict[-3])

    # Payload and AAD
    payload = b"Sensitive data"
    external_aad = b"context-12345"

    print("\n1. Signing with external AAD:")
    print(f"   Payload: {payload.decode()}")
    print(f"   External AAD: {external_aad.decode()}")

    # Sign with AAD
    cose_sign1_message = cose_sign1_sign(
        payload,
        signer,
        external_aad=external_aad
    )

    # Verify with correct AAD
    print("\n2. Verifying with correct AAD...")
    is_valid, _ = cose_sign1_verify(
        cose_sign1_message,
        verifier,
        external_aad=external_aad
    )
    print(f"   Result: {'✓ Valid' if is_valid else '✗ Invalid'}")

    # Try with wrong AAD
    print("\n3. Verifying with wrong AAD...")
    is_valid_wrong, _ = cose_sign1_verify(
        cose_sign1_message,
        verifier,
        external_aad=b"wrong-context"
    )
    print(f"   Result: {'✓ Valid' if is_valid_wrong else '✗ Invalid (as expected)'}")


def main():
    """Run all demos."""
    print("\n" + "#" * 60)
    print("# COSE Sign1 Library Demo")
    print("#" * 60)

    # Run demos
    demo_basic_sign_verify()
    demo_with_headers()
    demo_multiple_algorithms()
    demo_external_aad()

    print("\n" + "#" * 60)
    print("# Demo Complete!")
    print("#" * 60)


if __name__ == "__main__":
    main()
