#!/usr/bin/env python3
"""Demo script showing deterministic redaction with seeded salt generators."""

import cbor2
from sd_cwt import edn_to_redacted_cbor, SeededSaltGenerator, SecureSaltGenerator


def demonstrate_secure_vs_seeded():
    """Show the difference between secure and seeded salt generation."""
    print("=" * 60)
    print("Secure vs Seeded Salt Generation Demo")
    print("=" * 60)

    edn = '''
    {
        "iss": "https://issuer.example",
        "sub": "user123",
        "email": 59("alice@example.com"),
        "name": 59("Alice Smith"),
        "role": "admin"
    }
    '''

    print("Input EDN with 2 redacted claims:")
    print("-" * 40)
    print(edn.strip())

    # Demonstrate secure (non-deterministic) generation
    print("\n1. SECURE SALT GENERATION (default):")
    print("-" * 40)
    print("Running twice with default secure generator...")

    cbor1, _ = edn_to_redacted_cbor(edn)  # Uses SecureSaltGenerator by default
    cbor2, _ = edn_to_redacted_cbor(edn)

    hex1 = cbor1.hex()
    hex2 = cbor2.hex()

    print(f"Run 1 hex: {hex1[:60]}...")
    print(f"Run 2 hex: {hex2[:60]}...")
    print(f"Identical: {hex1 == hex2} (should be False - different random salts)")

    # Demonstrate seeded (deterministic) generation
    print("\n2. SEEDED SALT GENERATION (deterministic):")
    print("-" * 40)
    print("Running twice with same seed...")

    seed = 0x1234ABCD
    seeded_gen1 = SeededSaltGenerator(seed=seed)
    seeded_gen2 = SeededSaltGenerator(seed=seed)

    cbor3, disclosures3 = edn_to_redacted_cbor(edn, seeded_gen1)
    cbor4, disclosures4 = edn_to_redacted_cbor(edn, seeded_gen2)

    hex3 = cbor3.hex()
    hex4 = cbor4.hex()

    print(f"Run 1 hex: {hex3[:60]}...")
    print(f"Run 2 hex: {hex4[:60]}...")
    print(f"Identical: {hex3 == hex4} (should be True - same seed)")

    # Show disclosures are also identical
    print(f"\nDisclosures identical: {disclosures3 == disclosures4}")
    print(f"Number of disclosures: {len(disclosures3)}")

    return hex3, disclosures3


def demonstrate_reproducible_examples():
    """Show how to create reproducible examples for documentation."""
    print("\n" + "=" * 60)
    print("Reproducible Examples for Documentation")
    print("=" * 60)

    # Example claim set that might be used in documentation
    documentation_edn = '''
    {
        / Standard CWT claims /
        1: "https://issuer.example",      / iss /
        2: "device-001",                  / sub /
        4: 1725330600,                    / exp /
        6: 1725244200,                    / iat /

        / Public claims /
        "device_type": "sensor",
        "location": "building-A",
        "status": "active",

        / Redacted personal data /
        "user_id": 59("user_12345"),
        "user_email": 59("john.doe@company.com"),

        / Redacted sensitive data /
        "api_key": 59("sk_live_abc123def456"),
        "internal_id": 59(789012)
    }
    '''

    print("Documentation Example EDN:")
    print("-" * 40)
    print(documentation_edn.strip())

    # Use a fixed seed for documentation consistency
    DOC_SEED = 0x444F435F53454544  # "DOC_SEED" in hex

    seeded_gen = SeededSaltGenerator(seed=DOC_SEED)
    cbor_claims, disclosures = edn_to_redacted_cbor(documentation_edn, seeded_gen)

    hex_output = cbor_claims.hex()

    print(f"\nDocumentation Results:")
    print("-" * 40)
    print(f"CBOR hex (reproducible): {hex_output}")
    print(f"Length: {len(cbor_claims)} bytes")
    print(f"Redacted claims: {len(disclosures)}")

    # Decode to show structure
    claims = cbor2.loads(cbor_claims)
    print(f"\nClaims structure:")
    for key, value in claims.items():
        if isinstance(key, cbor2.CBORSimpleValue) and key.value == 59:
            print(f"  simple(59): {len(value)} disclosure hashes")
        else:
            print(f"  {key}: {value}")

    print(f"\nDisclosures (first 40 chars each):")
    for i, disclosure in enumerate(disclosures):
        decoded = cbor2.loads(disclosure)
        hex_short = disclosure.hex()[:40] + "..."
        print(f"  {i+1}. {decoded[2]} = {decoded[1]} | {hex_short}")

    # Verify reproducibility
    print(f"\n✓ Testing reproducibility...")
    seeded_gen2 = SeededSaltGenerator(seed=DOC_SEED)
    cbor_claims2, disclosures2 = edn_to_redacted_cbor(documentation_edn, seeded_gen2)

    print(f"  Identical CBOR: {cbor_claims == cbor_claims2}")
    print(f"  Identical disclosures: {disclosures == disclosures2}")

    return hex_output


def demonstrate_different_seeds():
    """Show how different seeds produce different outputs."""
    print("\n" + "=" * 60)
    print("Different Seeds Produce Different Outputs")
    print("=" * 60)

    edn = '''
    {
        "message": "Hello World",
        "secret": 59("top-secret-value"),
        "timestamp": 1725244200
    }
    '''

    seeds = [0x1111, 0x2222, 0x3333]
    results = []

    print("Same EDN with different seeds:")
    print("-" * 40)

    for i, seed in enumerate(seeds):
        seeded_gen = SeededSaltGenerator(seed=seed)
        cbor_claims, disclosures = edn_to_redacted_cbor(edn, seeded_gen)
        hex_output = cbor_claims.hex()
        results.append(hex_output)

        print(f"Seed 0x{seed:04X}: {hex_output[:50]}...")

    # Verify all different
    print(f"\nAll outputs unique: {len(set(results)) == len(results)}")

    return results


def main():
    """Run all demonstrations."""
    print("Deterministic Redaction Demo")
    print("Using seeded salt generators for reproducible outputs")

    # Run demonstrations
    hex1, disclosures1 = demonstrate_secure_vs_seeded()
    hex2 = demonstrate_reproducible_examples()
    results = demonstrate_different_seeds()

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print("✓ Secure salt generator: Non-deterministic (default)")
    print("✓ Seeded salt generator: Deterministic for testing")
    print("✓ Same seed always produces same output")
    print("✓ Different seeds produce different outputs")
    print("✓ Perfect for reproducible documentation examples")

    print(f"\nExample reproducible CBOR hex for docs:")
    print(f"{hex2}")


if __name__ == "__main__":
    main()