"""SD-CWT: SPICE SD-CWT specification implementation."""

from .cose_keys import (
    CoseAlgorithm,
    CoseEllipticCurve,
    CoseKeyType,
    cose_key_from_dict,
    cose_key_generate,
    cose_key_get_public,
    cose_key_thumbprint,
    cose_key_to_dict,
)
from .cose_sign1 import (
    ES256Signer,
    ES256Verifier,
    Signer,
    Verifier,
    cose_sign1_sign,
    cose_sign1_verify,
    generate_es256_key_pair,
)

__version__ = "0.1.0"


def main() -> None:
    """Main entry point for the sd-cwt library."""
    print("Hello from sd-cwt!")


__all__ = [
    "main",
    "__version__",
    # COSE Sign1
    "cose_sign1_sign",
    "cose_sign1_verify",
    "Signer",
    "Verifier",
    "ES256Signer",
    "ES256Verifier",
    "generate_es256_key_pair",
    # COSE Keys
    "cose_key_generate",
    "cose_key_from_dict",
    "cose_key_to_dict",
    "cose_key_get_public",
    "cose_key_thumbprint",
    "CoseAlgorithm",
    "CoseKeyType",
    "CoseEllipticCurve",
]
