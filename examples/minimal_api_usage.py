#!/usr/bin/env python3
"""Example of using the minimal public API for COSE Sign1."""

from typing import Any
import sd_cwt


class CustomSigner:
    """Example custom signer implementing the Signer protocol."""

    def __init__(self, cose_key_bytes: bytes):
        """Initialize with a COSE key."""
        self.key_dict = sd_cwt.cose_key_to_dict(cose_key_bytes)
        # In real implementation, extract private key and set up crypto

    def sign(self, message: bytes) -> bytes:
        """Sign a message."""
        # This is just a placeholder - real implementation would:
        # 1. Extract private key from self.key_dict[-4]
        # 2. Use appropriate crypto library to sign
        return b"signature_placeholder" + b"\x00" * 48  # Fake 64-byte signature

    @property
    def algorithm(self) -> int:
        """Get the algorithm from the key."""
        return self.key_dict.get(3, -7)  # Default to ES256


class CustomVerifier:
    """Example custom verifier implementing the Verifier protocol."""

    def __init__(self, cose_key_bytes: bytes):
        """Initialize with a COSE public key."""
        self.key_dict = sd_cwt.cose_key_to_dict(cose_key_bytes)
        # In real implementation, extract public key and set up crypto

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature."""
        # This is just a placeholder - real implementation would:
        # 1. Extract public key from self.key_dict[-2], self.key_dict[-3]
        # 2. Use appropriate crypto library to verify
        return len(signature) == 64  # Fake verification


def main():
    """Demonstrate minimal API usage."""
    print("SD-CWT Minimal API Example")
    print("=" * 40)

    # 1. Generate a COSE key (defaults to ES256)
    print("\n1. Generating COSE key...")
    cose_key = sd_cwt.cose_key_generate()
    print(f"   Generated key: {len(cose_key)} bytes")

    # 2. Get public key for sharing
    public_key = sd_cwt.cose_key_get_public(cose_key)
    print(f"   Public key: {len(public_key)} bytes")

    # 3. Calculate thumbprint for key identification
    thumbprint = sd_cwt.cose_key_thumbprint(public_key)
    print(f"   Thumbprint: {thumbprint.hex()[:16]}...")

    # 4. Create custom signer and verifier
    print("\n2. Creating custom signer/verifier...")
    signer = CustomSigner(cose_key)
    verifier = CustomVerifier(public_key)

    # 5. Sign a message
    payload = b"Hello, COSE!"
    print(f"\n3. Signing payload: {payload.decode()}")
    signed_message = sd_cwt.cose_sign1_sign(payload, signer)
    print(f"   Signed message: {len(signed_message)} bytes")

    # 6. Verify the message
    print("\n4. Verifying signature...")
    is_valid, recovered = sd_cwt.cose_sign1_verify(signed_message, verifier)
    print(f"   Valid: {is_valid}")
    if recovered:
        print(f"   Recovered: {recovered.decode()}")

    # 7. Generate other algorithm keys
    print("\n5. Other supported algorithms:")
    for alg in [sd_cwt.CoseAlgorithm.ES384, sd_cwt.CoseAlgorithm.EdDSA]:
        key = sd_cwt.cose_key_generate(alg)
        key_dict = sd_cwt.cose_key_to_dict(key)
        print(f"   {alg.name}: {len(key)} bytes, type={key_dict[1]}")


if __name__ == "__main__":
    main()