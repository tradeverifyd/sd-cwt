"""SD-CWT: SPICE SD-CWT specification implementation."""

from .cose_keys import (
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
from .sd_cwt import (
    create_sd_cwt_with_holder_binding,
    create_sd_cwt_presentation,
    validate_sd_cwt_presentation,
    extract_verified_claims,
)
from .verifiers import (
    CredentialVerifier,
    PresentationVerifier,
    get_presentation_verifier,
)
from .signers import (
    CredentialSigner,
    PresentationSigner,
    create_credential_signer,
    create_presentation_signer,
)
from .resolvers import (
    cose_key_thumbprint_resolver,
    cose_key_kid_resolver,
)
from .simple_api import (
    create_edn_with_annotations,
    create_presentation_edn,
    SDCWTIssuer,
    SDCWTPresenter,
    SDCWTVerifier,
)

# Hide module imports
from . import cose_keys, cose_sign1, redaction, sd_cwt, verifiers, signers, resolvers

del cose_keys, cose_sign1, redaction, sd_cwt, verifiers, signers, resolvers

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
    # EDN Redaction
    "edn_to_redacted_cbor",
    # Salt generators for deterministic testing
    "SaltGenerator",
    "SecureSaltGenerator",
    "SeededSaltGenerator",
    # SD-CWT with mandatory holder binding
    "create_sd_cwt_with_holder_binding",
    "create_sd_cwt_presentation",
    "validate_sd_cwt_presentation",
    "extract_verified_claims",
    # Verifiers for safe credential and presentation verification
    "CredentialVerifier",
    "PresentationVerifier",
    "get_presentation_verifier",
    # Signers for safe credential and presentation signing
    "CredentialSigner",
    "PresentationSigner",
    "create_credential_signer",
    "create_presentation_signer",
    # Resolvers for dynamic key resolution
    "cose_key_thumbprint_resolver",
    "cose_key_kid_resolver",
    # Simple APIs for SD-CWT workflow
    "create_edn_with_annotations",
    "create_presentation_edn",
    "SDCWTIssuer",
    "SDCWTPresenter",
    "SDCWTVerifier",
]
