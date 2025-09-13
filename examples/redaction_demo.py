#!/usr/bin/env python3
"""Demo script for EDN redaction functionality."""

import cbor2
from sd_cwt import edn_to_redacted_cbor


def main():
    """Demonstrate EDN redaction to CBOR hex output."""
    print("=" * 60)
    print("EDN Redaction Demo")
    print("=" * 60)

    # Example EDN with redaction tags
    edn_input = """
    {
        1: "https://issuer.example",      / iss /
        2: "user@example.com",            / sub /
        4: 1725330600,                    / exp /
        5: 1725243840,                    / nbf /
        6: 1725244200,                    / iat /

        / Redacted personal info /
        "name": 59("Alice Smith"),
        "email": 59("alice@example.com"),

        / Public role /
        "role": "admin",

        / Nested with partial redaction /
        "address": {
            "country": "US",
            "state": 59("CA"),
            "city": 59("San Francisco"),
            "public_zone": "West Coast"
        },

        / Fully redacted sensitive data /
        "payment_info": 59({
            "card_type": "visa",
            "last_four": "1234",
            "exp_date": "12/25"
        })
    }
    """

    print("Input EDN:")
    print("-" * 40)
    print(edn_input.strip())

    # Convert EDN to redacted CBOR
    print(f"\n{'Processing redactions...'}")
    cbor_claims, disclosures = edn_to_redacted_cbor(edn_input)

    # Convert to hex for sharing
    cbor_hex = cbor_claims.hex()

    print(f"\nResults:")
    print("-" * 40)
    print(f"CBOR Claims (hex): {cbor_hex}")
    print(f"CBOR Claims (bytes): {len(cbor_claims)} bytes")
    print(f"Number of disclosures: {len(disclosures)}")

    # Show what's in the redacted claims
    claims = cbor2.loads(cbor_claims)
    print(f"\nRedacted Claims Structure:")
    print("-" * 40)
    for key, value in claims.items():
        if isinstance(key, cbor2.CBORSimpleValue) and key.value == 59:
            print(f"  simple(59): {len(value)} disclosure hashes")
        else:
            print(f"  {key}: {value}")

    # Show disclosures
    print(f"\nDisclosures:")
    print("-" * 40)
    for i, disclosure in enumerate(disclosures):
        decoded = cbor2.loads(disclosure)
        salt_hex = decoded[0].hex()[:8] + "..."  # Show first 8 hex chars
        print(f"  {i+1}. Key: {decoded[2]}, Value: {decoded[1]}, Salt: {salt_hex}")
        print(f"      Disclosure hex: {disclosure.hex()}")

    print(f"\n{'='*60}")
    print("Complete CBOR hex for sharing:")
    print(f"{'='*60}")
    print(cbor_hex)

    return cbor_hex, disclosures


if __name__ == "__main__":
    main()