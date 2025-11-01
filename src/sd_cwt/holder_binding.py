from . import cbor_utils

"""SD-CWT Holder Binding implementation.

This module implements mandatory holder binding for SD-CWT according to the
latest IETF SPICE specification, including SD-KBT (Key Binding Token) generation.
"""

from typing import Any, Optional

from .cose_keys import cose_key_thumbprint, cose_key_to_dict
from .cose_sign1 import Signer, cose_sign1_sign


def create_cnf_claim(holder_key: bytes, use_thumbprint: bool = False) -> dict[int, Any]:
    """Create a confirmation (cnf) claim for holder binding.

    Args:
        holder_key: CBOR-encoded COSE key for the holder
        use_thumbprint: If True, use COSE Key Thumbprint (ckt) to reduce size

    Returns:
        Confirmation claim dictionary with structure:
        {1: COSE_Key} or {3: ckt_thumbprint}
    """
    if use_thumbprint:
        # Use COSE Key Thumbprint (RFC 9679) to reduce SD-CWT size
        thumbprint = cose_key_thumbprint(holder_key)
        return {3: thumbprint}  # ckt (COSE Key Thumbprint)
    else:
        # Include full COSE Key
        key_dict = cose_key_to_dict(holder_key)
        return {1: key_dict}  # COSE_Key


def extract_holder_key_from_cnf(cnf_claim: dict[int, Any]) -> Optional[bytes]:
    """Extract holder key from cnf claim.

    Args:
        cnf_claim: Confirmation claim from SD-CWT

    Returns:
        CBOR-encoded holder key if found, None otherwise
    """
    if 1 in cnf_claim:
        # Full COSE Key
        return cbor_utils.encode(cnf_claim[1])
    elif 3 in cnf_claim:
        # COSE Key Thumbprint - cannot reconstruct key
        return None
    return None


def create_sd_kbt(
    sd_cwt_with_disclosures: bytes,
    holder_signer: Signer,
    audience: str,
    issued_at: int,
    cnonce: Optional[bytes] = None,
    key_id: Optional[bytes] = None,
) -> bytes:
    """Create an SD-CWT Key Binding Token (SD-KBT).

    The SD-KBT proves possession of the holder's private key and binds
    the disclosures to a specific verifier and time.

    Args:
        sd_cwt_with_disclosures: Complete SD-CWT with disclosures
        holder_signer: Signer using holder's private key
        audience: Verifier identifier (aud claim)
        issued_at: Issuance time (iat claim)
        cnonce: Optional challenge nonce from verifier
        key_id: Optional key identifier

    Returns:
        CBOR-encoded SD-KBT (COSE Sign1 message)
    """
    # SD-KBT payload (CWT Claims Set)
    kbt_payload = {
        3: audience,  # aud - REQUIRED: corresponds to the Verifier
        6: issued_at,  # iat - REQUIRED: issued at time
    }

    # Add optional cnonce if provided
    if cnonce is not None:
        kbt_payload[39] = cnonce  # cnonce

    # Protected header for SD-KBT
    protected_header = {
        1: holder_signer.algorithm,  # Algorithm
        16: "application/kb+cwt",  # typ header parameter (REQUIRED)
        TBD_KCWT: sd_cwt_with_disclosures,  # kcwt - contains the full SD-CWT
    }

    # Add key ID if provided
    if key_id is not None:
        protected_header[4] = key_id  # kid

    # Unprotected header (empty for SD-KBT)
    unprotected_header: dict[str, Any] = {}

    # Encode payload
    payload_bytes = cbor_utils.encode(kbt_payload)

    # Sign the SD-KBT
    sd_kbt = cose_sign1_sign(
        payload_bytes,
        holder_signer,
        protected_header=protected_header,
        unprotected_header=unprotected_header,
    )

    return sd_kbt


def create_sd_cwt_with_mandatory_cnf(
    base_claims: dict[Any, Any],
    holder_key: bytes,
    sd_hashes: list[bytes],
    use_thumbprint: bool = False,
) -> dict[Any, Any]:
    """Create SD-CWT claims with mandatory cnf claim.

    Args:
        base_claims: Base claims dictionary
        holder_key: CBOR-encoded holder key (REQUIRED)
        sd_hashes: List of disclosure hashes
        use_thumbprint: Whether to use COSE Key Thumbprint

    Returns:
        Complete SD-CWT claims with mandatory cnf
    """
    # Start with base claims
    sd_cwt_claims = base_claims.copy()

    # Add mandatory cnf claim (holder binding is REQUIRED)
    cnf_claim = create_cnf_claim(holder_key, use_thumbprint)
    sd_cwt_claims[8] = cnf_claim  # cnf claim (REQUIRED)

    # Add selective disclosure hashes if present
    if sd_hashes:
        sd_cwt_claims[cbor_utils.create_simple_value(59)] = sd_hashes

    return sd_cwt_claims


def validate_sd_cwt_cnf(sd_cwt_claims: dict[Any, Any]) -> bool:
    """Validate that SD-CWT contains mandatory cnf claim.

    Args:
        sd_cwt_claims: SD-CWT claims dictionary

    Returns:
        True if cnf claim is present and valid, False otherwise
    """
    # Check cnf claim is present
    if 8 not in sd_cwt_claims:
        return False

    cnf_claim = sd_cwt_claims[8]
    if not isinstance(cnf_claim, dict):
        return False

    # Must have either COSE_Key (1) or COSE Key Thumbprint (3)
    return (1 in cnf_claim) or (3 in cnf_claim)


def validate_sd_kbt_structure(sd_kbt: bytes) -> tuple[bool, Optional[dict[str, Any]]]:
    """Validate SD-KBT structure according to specification.

    Args:
        sd_kbt: CBOR-encoded SD-KBT

    Returns:
        Tuple of (is_valid, extracted_info)
        extracted_info contains aud, iat, cnonce, and kcwt if valid
    """
    try:
        # Decode COSE Sign1
        decoded = cbor_utils.decode(sd_kbt)
        if cbor_utils.is_tag(decoded) and cbor_utils.get_tag_number(decoded) == 18:
            cose_sign1 = cbor_utils.get_tag_value(decoded)
        else:
            return False, None

        if not isinstance(cose_sign1, list) or len(cose_sign1) != 4:
            return False, None

        protected_header_bytes, unprotected_header, payload, signature = cose_sign1

        # Decode protected header
        if protected_header_bytes:
            protected_header = cbor_utils.decode(protected_header_bytes)
        else:
            return False, None

        # Check required protected header fields
        if 16 not in protected_header:  # typ
            return False, None

        typ_value = protected_header[16]
        if typ_value != "application/kb+cwt":
            return False, None

        if TBD_KCWT not in protected_header:  # kcwt
            return False, None

        # Decode payload
        kbt_claims = cbor_utils.decode(payload)

        # Check required claims
        if 3 not in kbt_claims or 6 not in kbt_claims:  # aud and iat
            return False, None

        extracted_info = {
            "aud": kbt_claims[3],
            "iat": kbt_claims[6],
            "cnonce": kbt_claims.get(39),  # Optional
            "kcwt": protected_header[TBD_KCWT],
            "kid": protected_header.get(4),  # Optional
        }

        return True, extracted_info

    except Exception:
        return False, None


# Temporary constant until IANA registration
TBD_KCWT = 13  # Placeholder for kcwt header parameter
