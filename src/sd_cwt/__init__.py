"""SD-CWT: SPICE SD-CWT specification implementation."""

from .cose_keys import (
    CoseAlgorithm,
    cose_key_from_dict,
    cose_key_generate,
    cose_key_get_public,
    cose_key_thumbprint,
    cose_key_to_dict,
)
from .cose_sign1 import (
    Signer,
    Verifier,
    cose_sign1_sign,
    cose_sign1_verify,
)
from .redaction import (
    SecureSaltGenerator,
    SeededSaltGenerator,
    SaltGenerator,
    edn_to_redacted_cbor,
)

# Hide module imports
del cose_keys
del cose_sign1
del redaction

__version__ = "0.1.0"


__all__ = [
    "__version__",
    # COSE Sign1 - Core functions
    "cose_sign1_sign",
    "cose_sign1_verify",
    # Protocols for custom implementations
    "Signer",
    "Verifier",
    # COSE Keys - Core functions
    "cose_key_generate",
    "cose_key_from_dict",
    "cose_key_to_dict",
    "cose_key_get_public",
    "cose_key_thumbprint",
    # Algorithm enumeration (needed for key generation)
    "CoseAlgorithm",
    # EDN Redaction
    "edn_to_redacted_cbor",
    # Salt generators for deterministic testing
    "SaltGenerator",
    "SecureSaltGenerator",
    "SeededSaltGenerator",
]
