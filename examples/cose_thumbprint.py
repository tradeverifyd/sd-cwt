#!/usr/bin/env python3
"""Example demonstrating COSE Key Thumbprint computation (RFC 9679)."""

import base64

from sd_cwt.thumbprint import CoseKeyThumbprint


def demonstrate_ec2_thumbprint():
    """Demonstrate EC2 key thumbprint computation."""
    print("=" * 60)
    print("EC2 (P-256) Key Thumbprint Demo")
    print("=" * 60)

    # Sample EC2 key
    ec2_key = {
        1: 2,  # kty: EC2
        3: -7,  # alg: ES256 (will be excluded from thumbprint)
        -1: 1,  # crv: P-256
        -2: base64.b64decode("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8="),  # x
        -3: base64.b64decode("IBOL+C3BttVivg+lSreASjpkttcsz+1rb7btKLv8EX4="),  # y
        "kid": "example-key-1",  # Also excluded from thumbprint
    }

    print("\n1. Original COSE Key (with optional fields):")
    print(f"   Key ID: {ec2_key.get('kid')}")
    print(f"   Algorithm: {ec2_key.get(3)} (ES256)")
    print(f"   Key Type: {ec2_key[1]} (EC2)")
    print(f"   Curve: {ec2_key[-1]} (P-256)")

    # Compute thumbprint with SHA-256
    thumbprint_sha256 = CoseKeyThumbprint.compute(ec2_key, "sha256")
    print("\n2. SHA-256 Thumbprint:")
    print(f"   Hex: {thumbprint_sha256.hex()}")
    print(f"   Base64url: {base64.urlsafe_b64encode(thumbprint_sha256).rstrip(b'=').decode()}")

    # Compute thumbprint URI
    uri = CoseKeyThumbprint.uri(ec2_key, "sha256")
    print("\n3. Thumbprint URI:")
    print(f"   {uri}")

    # Show that optional fields don't affect thumbprint
    ec2_key_minimal = {
        1: 2,  # kty
        -1: 1,  # crv
        -2: ec2_key[-2],  # x
        -3: ec2_key[-3],  # y
    }

    thumbprint_minimal = CoseKeyThumbprint.compute(ec2_key_minimal, "sha256")
    print("\n4. Verification - Same thumbprint without optional fields:")
    print(f"   Thumbprints match: {thumbprint_sha256 == thumbprint_minimal}")


def demonstrate_okp_thumbprint():
    """Demonstrate OKP key thumbprint computation."""
    print("\n" + "=" * 60)
    print("OKP (Ed25519) Key Thumbprint Demo")
    print("=" * 60)

    # Sample OKP key
    okp_key = {
        1: 1,  # kty: OKP
        3: -8,  # alg: EdDSA
        -1: 6,  # crv: Ed25519
        -2: base64.b64decode("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="),  # x
    }

    print("\n1. OKP Key:")
    print(f"   Key Type: {okp_key[1]} (OKP)")
    print(f"   Curve: {okp_key[-1]} (Ed25519)")

    # Compute thumbprint
    thumbprint = CoseKeyThumbprint.compute(okp_key, "sha256")
    print("\n2. SHA-256 Thumbprint:")
    print(f"   Hex: {thumbprint.hex()}")

    # URI format
    uri = CoseKeyThumbprint.uri(okp_key, "sha256")
    print("\n3. Thumbprint URI:")
    print(f"   {uri}")


def demonstrate_multiple_hash_algorithms():
    """Demonstrate thumbprints with different hash algorithms."""
    print("\n" + "=" * 60)
    print("Multiple Hash Algorithms Demo")
    print("=" * 60)

    # Simple symmetric key
    symmetric_key = {
        1: 4,  # kty: Symmetric
        -1: base64.b64decode("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg="),  # k
    }

    print("\n1. Symmetric Key Thumbprints:")

    for hash_alg in ["sha256", "sha384", "sha512"]:
        thumbprint = CoseKeyThumbprint.compute(symmetric_key, hash_alg)
        uri = CoseKeyThumbprint.uri(symmetric_key, hash_alg)
        print(f"\n   {hash_alg.upper()}:")
        print(f"     Length: {len(thumbprint)} bytes")
        print(f"     Hex: {thumbprint.hex()[:32]}...")
        print(f"     URI: {uri[:60]}...")


def demonstrate_canonical_cbor():
    """Demonstrate canonical CBOR encoding for thumbprint."""
    print("\n" + "=" * 60)
    print("Canonical CBOR Encoding Demo")
    print("=" * 60)

    # EC2 key with fields in non-canonical order
    ec2_key = {
        -3: b"y_coordinate",  # y
        1: 2,  # kty
        3: -7,  # alg (will be excluded)
        -2: b"x_coordinate",  # x
        -1: 1,  # crv
        "extra": "ignored",  # Extra field (will be excluded)
    }

    print("\n1. Original key order:")
    print(f"   Fields: {list(ec2_key.keys())}")

    # Get canonical CBOR
    canonical = CoseKeyThumbprint.canonical_cbor(ec2_key)

    print("\n2. Canonical encoding:")
    print(f"   CBOR hex: {canonical.hex()}")
    print(f"   Length: {len(canonical)} bytes")

    # Compute thumbprint
    import hashlib
    thumbprint = hashlib.sha256(canonical).digest()

    print("\n3. Resulting thumbprint:")
    print(f"   SHA-256: {thumbprint.hex()}")

    # Show it's deterministic
    canonical2 = CoseKeyThumbprint.canonical_cbor(ec2_key)
    print("\n4. Deterministic result:")
    print(f"   Same canonical CBOR: {canonical == canonical2}")


def main():
    """Run all demonstrations."""
    print("\nCOSE Key Thumbprint (RFC 9679) Examples")
    print("=" * 60)

    demonstrate_ec2_thumbprint()
    demonstrate_okp_thumbprint()
    demonstrate_multiple_hash_algorithms()
    demonstrate_canonical_cbor()

    print("\n" + "=" * 60)
    print("Demo completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
