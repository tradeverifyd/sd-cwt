from . import cbor_utils

"""Complete SD-CWT implementation with mandatory holder binding.

This module provides high-level functions for creating SD-CWTs with mandatory
confirmation claims and SD-KBTs according to the IETF SPICE specification.
"""

from typing import Any, Optional

from .cose_keys import cose_key_generate
from .cose_sign1 import Signer, cose_sign1_sign
from .holder_binding import (
    create_sd_cwt_with_mandatory_cnf,
    create_sd_kbt,
    validate_sd_cwt_cnf,
)
from .redaction import (
    SaltGenerator,
    edn_to_redacted_cbor,
)


def create_sd_cwt_with_holder_binding(
    edn_claims: str,
    issuer_signer: Signer,
    holder_key: Optional[bytes] = None,
    use_thumbprint: bool = False,
    salt_generator: Optional[SaltGenerator] = None,
    issuer_key_id: Optional[bytes] = None
) -> dict[str, Any]:
    """Create a complete SD-CWT with mandatory holder binding.

    According to the SD-CWT specification, holder binding is REQUIRED.
    This function ensures the cnf claim is always present.

    Args:
        edn_claims: Claims in EDN format with redaction tags
        issuer_signer: Signer for the issuer's signing key
        holder_key: CBOR-encoded holder key (auto-generated if None)
        use_thumbprint: Use COSE Key Thumbprint to reduce size
        salt_generator: Optional salt generator for deterministic testing
        issuer_key_id: Optional key ID for issuer

    Returns:
        Dictionary containing:
        - sd_cwt: The signed SD-CWT with mandatory cnf claim (bytes)
        - disclosures: List of disclosure arrays (bytes)
        - holder_key: The holder's key for binding (bytes)
    """
    # Generate holder key if not provided (holder binding is REQUIRED)
    if holder_key is None:
        holder_key = cose_key_generate()

    # Process EDN claims with redaction
    cbor_claims, disclosures = edn_to_redacted_cbor(edn_claims, salt_generator)
    base_claims = cbor_utils.decode(cbor_claims)

    # Extract SD hashes if present
    sd_hashes = []
    simple_59 = cbor_utils.create_simple_value(59)
    if simple_59 in base_claims:
        sd_hashes = base_claims[simple_59]
        del base_claims[simple_59]  # Remove before adding cnf

    # Create SD-CWT claims with mandatory cnf claim
    sd_cwt_claims = create_sd_cwt_with_mandatory_cnf(
        base_claims, holder_key, sd_hashes, use_thumbprint
    )

    # Create protected header for issuer signature
    protected_header = {
        1: issuer_signer.algorithm,  # Algorithm
    }

    # Add issuer key ID if provided
    if issuer_key_id is not None:
        protected_header[4] = issuer_key_id  # kid

    # Encode payload
    payload = cbor_utils.encode(sd_cwt_claims)

    # Sign the SD-CWT
    sd_cwt = cose_sign1_sign(
        payload,
        issuer_signer,
        protected_header=protected_header
    )

    return {
        "sd_cwt": sd_cwt,
        "disclosures": disclosures,
        "holder_key": holder_key
    }


def create_sd_cwt_presentation(
    sd_cwt: bytes,
    all_disclosures: list[bytes],
    selected_disclosure_indices: list[int],
    holder_signer: Signer,
    verifier_audience: str,
    issued_at: int,
    cnonce: Optional[bytes] = None,
    holder_key_id: Optional[bytes] = None
) -> bytes:
    """Create an SD-CWT presentation with selected disclosures and SD-KBT.

    Args:
        sd_cwt: The original SD-CWT from issuer
        all_disclosures: All available disclosures
        selected_disclosure_indices: Which disclosures to include
        holder_signer: Signer using holder's private key
        verifier_audience: Verifier identifier for aud claim
        issued_at: Time of presentation (iat claim)
        cnonce: Optional challenge nonce from verifier
        holder_key_id: Optional holder key identifier

    Returns:
        CBOR-encoded SD-KBT containing the SD-CWT and selected disclosures
    """
    # Select disclosures
    selected_disclosures = [all_disclosures[i] for i in selected_disclosure_indices]

    # Create SD-CWT with selected disclosures structure
    sd_cwt_with_disclosures_dict = {
        "sd_cwt": sd_cwt,
        "disclosures": selected_disclosures
    }
    sd_cwt_with_disclosures = cbor_utils.encode(sd_cwt_with_disclosures_dict)

    # Create and return SD-KBT
    return create_sd_kbt(
        sd_cwt_with_disclosures,
        holder_signer,
        verifier_audience,
        issued_at,
        cnonce,
        holder_key_id
    )


def validate_sd_cwt_presentation(sd_kbt: bytes) -> dict[str, Any]:
    """Validate an SD-CWT presentation (SD-KBT).

    Args:
        sd_kbt: CBOR-encoded SD-KBT

    Returns:
        Validation result dictionary containing:
        - valid: Boolean indicating if presentation is valid
        - sd_cwt: Extracted SD-CWT if valid
        - disclosures: Extracted disclosures if valid
        - audience: Verifier audience from aud claim
        - issued_at: Presentation time from iat claim
        - cnonce: Challenge nonce if present
        - errors: List of validation errors
    """
    from .holder_binding import validate_sd_kbt_structure

    result = {
        "valid": False,
        "sd_cwt": None,
        "disclosures": [],
        "audience": None,
        "issued_at": None,
        "cnonce": None,
        "errors": []
    }

    # Validate SD-KBT structure
    is_valid, extracted_info = validate_sd_kbt_structure(sd_kbt)
    if not is_valid or extracted_info is None:
        result["errors"].append("Invalid SD-KBT structure")
        return result

    try:
        # Extract SD-CWT with disclosures
        sd_cwt_with_disclosures = cbor_utils.decode(extracted_info["kcwt"])

        if not isinstance(sd_cwt_with_disclosures, dict):
            result["errors"].append("Invalid SD-CWT with disclosures format")
            return result

        sd_cwt = sd_cwt_with_disclosures.get("sd_cwt")
        disclosures = sd_cwt_with_disclosures.get("disclosures", [])

        if sd_cwt is None:
            result["errors"].append("Missing SD-CWT in presentation")
            return result

        # Validate SD-CWT has mandatory cnf claim
        sd_cwt_payload = cbor_utils.decode(sd_cwt)
        if cbor_utils.is_tag(sd_cwt_payload) and cbor_utils.get_tag_number(sd_cwt_payload) == 18:
            cose_sign1 = cbor_utils.get_tag_value(sd_cwt_payload)
            sd_cwt_claims = cbor_utils.decode(cose_sign1[2])  # payload
        else:
            result["errors"].append("Invalid SD-CWT format")
            return result

        if not validate_sd_cwt_cnf(sd_cwt_claims):
            result["errors"].append("SD-CWT missing mandatory cnf claim")
            return result

        # Success
        result.update({
            "valid": True,
            "sd_cwt": sd_cwt,
            "disclosures": disclosures,
            "audience": extracted_info["aud"],
            "issued_at": extracted_info["iat"],
            "cnonce": extracted_info["cnonce"]
        })

    except Exception as e:
        result["errors"].append(f"Validation error: {str(e)}")

    return result


def extract_verified_claims(sd_kbt: bytes) -> dict[str, Any]:
    """Extract verified claims from a validated SD-CWT presentation.

    This function returns a closed claimset with no redacted elements,
    suitable for CDDL validation by a verifier.

    Args:
        sd_kbt: CBOR-encoded SD-KBT (validated presentation)

    Returns:
        Dictionary containing:
        - valid: Boolean indicating if extraction succeeded
        - claims: Complete claims map with disclosed values (if valid)
        - errors: List of errors encountered
    """
    result = {
        "valid": False,
        "claims": {},
        "errors": []
    }

    # First validate the presentation
    validation_result = validate_sd_cwt_presentation(sd_kbt)
    if not validation_result["valid"]:
        result["errors"] = validation_result["errors"]
        return result

    try:
        # Extract SD-CWT and disclosures from validated result
        sd_cwt = validation_result["sd_cwt"]
        disclosures = validation_result["disclosures"]

        # Decode the SD-CWT to get base claims
        decoded_sd_cwt = cbor_utils.decode(sd_cwt)
        if cbor_utils.is_tag(decoded_sd_cwt) and cbor_utils.get_tag_number(decoded_sd_cwt) == 18:
            cose_sign1 = cbor_utils.get_tag_value(decoded_sd_cwt)
            base_claims = cbor_utils.decode(cose_sign1[2])  # payload
        else:
            result["errors"].append("Invalid SD-CWT structure")
            return result

        # Start with base claims (non-redacted)
        verified_claims = base_claims.copy()

        # Remove the redacted claim hashes (simple value 59) - these are replaced by actual claims
        simple_59 = cbor_utils.create_simple_value(59)
        if simple_59 in verified_claims:
            del verified_claims[simple_59]

        # Add disclosed claims from disclosures
        for disclosure_bytes in disclosures:
            disclosure = cbor_utils.decode(disclosure_bytes)
            # SD-CWT disclosure format: [salt, claim_value, claim_name]
            claim_name = disclosure[2]  # claim key
            claim_value = disclosure[1]  # claim value
            verified_claims[claim_name] = claim_value

        result["valid"] = True
        result["claims"] = verified_claims

    except Exception as e:
        result["errors"].append(f"Claims extraction error: {str(e)}")

    return result
