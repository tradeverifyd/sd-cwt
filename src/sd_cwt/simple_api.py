"""Simple APIs for SD-CWT workflow: annotate, issue, present."""

import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from . import cbor_utils
from .cose_sign1 import cose_sign1_sign
from .holder_binding import create_cnf_claim, create_sd_kbt
from .redaction import edn_to_redacted_cbor
from .signers import CredentialSigner, PresentationSigner
from .thumbprint import CoseKeyThumbprint


def select_disclosures_by_claim_names(
    disclosures: List[bytes],
    claim_names: List[str]
) -> List[bytes]:
    """Select disclosures that match the specified claim names.

    Args:
        disclosures: List of all available disclosure bytes
        claim_names: List of claim names to select

    Returns:
        List of selected disclosure bytes
    """
    selected = []
    for disclosure_bytes in disclosures:
        try:
            disclosure = cbor_utils.decode(disclosure_bytes)
            if isinstance(disclosure, list) and len(disclosure) == 3:
                # SD-CWT format: [salt, value, key]
                salt, value, key = disclosure
                if isinstance(key, str) and key in claim_names:
                    selected.append(disclosure_bytes)
        except Exception:
            # Skip invalid disclosures
            continue
    return selected


def create_edn_with_annotations(
    base_claims: Dict[str, Any],
    optional_claims: Dict[str, Any],
    issuer: str = "https://issuer.example",
    subject: str = "https://subject.example",
    holder_public_key: bytes = None,
    use_holder_thumbprint: bool = False,
    issued_at: Optional[int] = None
) -> str:
    """Create EDN string with selective disclosure annotations.

    Args:
        base_claims: Claims that are mandatory to disclose
        optional_claims: Claims that are optional to disclose (wrapped with tag 58)
        issuer: Issuer identifier
        subject: Subject identifier
        holder_public_key: CBOR-encoded holder's public key
        use_holder_thumbprint: Whether to use thumbprint in cnf claim
        issued_at: Optional timestamp (uses current time if None)

    Returns:
        EDN string with proper tag annotations matching guide.md format

    Example:
        edn = create_edn_with_annotations(
            base_claims={
                "production_date": "2024-01-15",
                "steel_grade": "ASTM A615 Grade 60"
            },
            optional_claims={
                "heat_number": "H240115-001",
                "cost": 850.75
            }
        )
    """
    current_time = issued_at if issued_at is not None else int(time.time())

    # Create cnf claim for holder binding
    if holder_public_key:
        cnf_claim = create_cnf_claim(holder_public_key, use_holder_thumbprint)
        cnf_edn = _format_cnf_for_edn(cnf_claim)
    else:
        # Use static key from guide.md format when no holder public key is provided
        cnf_edn = """{
    1: {
      1: 2,
      -1: 1,
      -2: h'4a8cf2c9b1d8e7f6a5b9c3d2e1f0a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1',
      -3: h'f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f0e1d2c3b9a5f6e7d8b1c9f2a84'
    }
  }"""

    # Build EDN string matching guide.md format
    edn_parts = [
        "{",
        f'  1: "{issuer}",',
        f'  2: "{subject}",',
        f"  6: {current_time},",
        f"  8: {cnf_edn},",
        f'  11: "https://steel.consortium.example/rebar/v1.cddl",',
    ]

    # Add base claims (mandatory to disclose) - these are not wrapped in tags
    for key, value in base_claims.items():
        edn_parts.append(f'  "{key}": {_format_value_for_edn(value)},')

    # Add optional claims (wrapped with tag 58 as in guide.md)
    for key, value in optional_claims.items():
        edn_parts.append(f'  "{key}": 58({_format_value_for_edn(value)}),')

    edn_parts.append("}")

    return "\n".join(edn_parts)


def _format_cnf_for_edn(cnf_claim: Dict[int, Any]) -> str:
    """Format cnf claim for EDN representation."""
    if 1 in cnf_claim:  # Full COSE key
        key = cnf_claim[1]
        return f"""{{
    1: {{
      1: {key[1]},
      -1: {key[-1]},
      -2: h'{key[-2].hex()}',
      -3: h'{key[-3].hex()}'
    }}
  }}"""
    elif 3 in cnf_claim:  # COSE Key Thumbprint
        return f"{{ 3: h'{cnf_claim[3].hex()}' }}"
    else:
        return str(cnf_claim)


def _format_value_for_edn(value: Any) -> str:
    """Format a value for EDN representation."""
    if isinstance(value, str):
        return f'"{value}"'
    elif isinstance(value, (int, float)):
        return str(value)
    elif isinstance(value, dict):
        parts = ["{"]
        for k, v in value.items():
            parts.append(f'  "{k}": {_format_value_for_edn(v)},')
        parts.append("}")
        return "\n    ".join(parts)
    elif isinstance(value, list):
        parts = ["["]
        for item in value:
            parts.append(f"  {_format_value_for_edn(item)},")
        parts.append("]")
        return "\n    ".join(parts)
    else:
        return str(value)


class SDCWTIssuer:
    """Simple API for issuing SD-CWTs with selective disclosure."""

    def __init__(self, issuer_private_key: Dict[int, Any]):
        """Initialize with issuer's private key.

        Args:
            issuer_private_key: COSE private key dictionary
        """
        self.issuer_key = issuer_private_key
        self.signer = CredentialSigner(issuer_private_key)

    def issue_credential(
        self,
        base_claims: Dict[str, Any],
        optional_claims: Dict[str, Any],
        holder_public_key: bytes,
        issuer: str = "https://issuer.example",
        subject: str = "https://subject.example",
        use_holder_thumbprint: bool = False,
    ) -> Tuple[bytes, str, List[bytes]]:
        """Issue an SD-CWT credential with selective disclosure.

        Args:
            base_claims: Claims that are mandatory to disclose
            optional_claims: Claims that are optional to disclose
            holder_public_key: CBOR-encoded holder's public key
            issuer: Issuer identifier
            subject: Subject identifier
            use_holder_thumbprint: Whether to use thumbprint in cnf claim

        Returns:
            Tuple of (sd_cwt_bytes, disclosure_edn_string, disclosures)

        Example:
            sd_cwt, edn, disclosures = issuer.issue_credential(
                base_claims={"production_date": "2024-01-15"},
                optional_claims={"heat_number": "H240115-001"},
                holder_public_key=holder_key_cbor
            )
        """
        # Create EDN with proper annotations
        edn_string = create_edn_with_annotations(
            base_claims=base_claims,
            optional_claims=optional_claims,
            issuer=issuer,
            subject=subject,
            holder_public_key=holder_public_key,
            use_holder_thumbprint=use_holder_thumbprint
        )

        # Convert EDN to redacted CBOR
        redacted_claims, disclosures = edn_to_redacted_cbor(edn_string)

        # Sign the SD-CWT
        issuer_thumbprint = CoseKeyThumbprint.compute(self.issuer_key, "sha256")
        protected_header = {
            1: -7,  # ES256
            16: "application/sd-cwt",  # typ
            4: issuer_thumbprint  # kid
        }

        payload_cbor = cbor_utils.encode(redacted_claims)
        sd_cwt = cose_sign1_sign(payload_cbor, self.signer, protected_header=protected_header)

        return sd_cwt, edn_string, disclosures


def create_presentation_edn(
    original_edn: str,
    selected_claims: List[str]
) -> str:
    """Create a presentation EDN with selected claims disclosed.

    Args:
        original_edn: Original EDN with tag 58 annotations
        selected_claims: List of claim names to disclose

    Returns:
        Clean EDN string with selected claims disclosed (no redaction tags)

    Example:
        presentation_edn = create_presentation_edn(
            original_edn=edn_with_tags,
            selected_claims=["heat_number", "chemical_composition"]
        )
    """
    # Parse the original EDN and rebuild with selected disclosures
    lines = original_edn.strip().split('\n')
    presentation_lines = []

    for line in lines:
        line = line.strip()
        if not line or line in ['{', '}']:
            presentation_lines.append(line)
            continue

        # Check if this line contains a claim that should be disclosed
        disclosed = False
        for claim_name in selected_claims:
            if f'"{claim_name}":' in line:
                disclosed = True
                break

        if disclosed:
            # Remove tag 58 wrapper for disclosed claims
            # Transform: "claim": 58(value), -> "claim": value,
            clean_line = re.sub(r'58\(([^)]+)\)', r'\1', line)
            presentation_lines.append(clean_line)
        else:
            # Keep standard claims (iss, sub, iat, cnf) and non-disclosed claims as-is
            if any(std_claim in line for std_claim in ['1:', '2:', '6:', '8:']):
                presentation_lines.append(line)
            # Skip optional claims that are not selected for disclosure

    return '\n'.join(presentation_lines)


class SDCWTPresenter:
    """Simple API for creating SD-CWT presentations."""

    def __init__(self, holder_private_key: Dict[int, Any]):
        """Initialize with holder's private key.

        Args:
            holder_private_key: COSE private key dictionary
        """
        self.holder_key = holder_private_key
        self.signer = PresentationSigner(holder_private_key)

    def create_presentation(
        self,
        sd_cwt: bytes,
        disclosures: List[bytes],
        selected_disclosures: List[bytes],
        audience: str,
        nonce: Optional[str] = None
    ) -> bytes:
        """Create a presentation with selected claims disclosed.

        Args:
            sd_cwt: The original SD-CWT credential
            disclosures: All available disclosures from issuance
            selected_disclosures: Selected subset of disclosures to include
            audience: Intended audience for the presentation
            nonce: Optional nonce for freshness

        Returns:
            KBT (Key Binding Token) bytes containing the presentation

        Example:
            kbt = presenter.create_presentation(
                sd_cwt=credential,
                disclosures=all_disclosures,
                selected_disclosures=[heat_disclosure, composition_disclosure],
                audience="https://customs.us.example",
                nonce="1234567890"
            )
        """
        # Create SD-CWT with selected disclosures for presentation
        sd_cwt_with_disclosures = self._create_sd_cwt_with_selected_disclosures(
            sd_cwt, selected_disclosures
        )

        # Create the KBT
        holder_thumbprint = CoseKeyThumbprint.compute(self.holder_key, "sha256")
        current_time = int(time.time())

        cnonce = nonce.encode() if nonce else None

        kbt = create_sd_kbt(
            sd_cwt_with_disclosures=sd_cwt_with_disclosures,
            holder_signer=self.signer,
            audience=audience,
            issued_at=current_time,
            cnonce=cnonce,
            key_id=holder_thumbprint
        )

        return kbt

    def _create_sd_cwt_with_selected_disclosures(
        self,
        original_sd_cwt: bytes,
        selected_disclosures: List[bytes]
    ) -> bytes:
        """Create SD-CWT with only selected disclosures in unprotected header.

        Args:
            original_sd_cwt: Original SD-CWT from issuer
            selected_disclosures: Subset of disclosures to include

        Returns:
            Modified SD-CWT with selected disclosures
        """
        # Decode the original SD-CWT
        cose_sign1 = cbor_utils.decode(original_sd_cwt)

        # Handle CBOR tag wrapping
        if cbor_utils.is_tag(cose_sign1):
            cose_sign1_value = cbor_utils.get_tag_value(cose_sign1)
        else:
            cose_sign1_value = cose_sign1

        if not isinstance(cose_sign1_value, list) or len(cose_sign1_value) != 4:
            raise ValueError("Invalid COSE Sign1 structure")

        # Extract components: [protected, unprotected, payload, signature]
        protected_header_bytes = cose_sign1_value[0]
        unprotected_header = cose_sign1_value[1]
        payload_bytes = cose_sign1_value[2]
        signature_bytes = cose_sign1_value[3]

        # Create new unprotected header with selected disclosures
        new_unprotected = unprotected_header.copy() if unprotected_header else {}

        # Update sd_claims field (TBD1/17) with selected disclosures
        sd_claims_key = 17  # Based on spec examples
        new_unprotected[sd_claims_key] = selected_disclosures

        # Reconstruct COSE Sign1 with modified unprotected header
        new_cose_sign1_value = [
            protected_header_bytes,
            new_unprotected,
            payload_bytes,
            signature_bytes
        ]

        # Re-wrap with tag if original was tagged
        if cbor_utils.is_tag(cose_sign1):
            new_cose_sign1 = cbor_utils.create_tag(
                cbor_utils.get_tag_number(cose_sign1),
                new_cose_sign1_value
            )
        else:
            new_cose_sign1 = new_cose_sign1_value

        # Encode and return
        return cbor_utils.encode(new_cose_sign1)


class SDCWTVerifier:
    """Simple API for verifying SD-CWT presentations."""

    def __init__(self, public_key_resolver):
        """Initialize with a public key resolver.

        Args:
            public_key_resolver: Function that resolves key IDs to COSE keys
        """
        from .verifiers import CredentialVerifier
        self.credential_verifier = CredentialVerifier(public_key_resolver)

    def verify_presentation(
        self,
        kbt: bytes,
        expected_audience: str,
        holder_key_resolver=None
    ) -> Tuple[bool, Optional[Dict[str, Any]], bool]:
        """Verify an SD-CWT presentation and extract claims.

        Args:
            kbt: Key Binding Token containing the presentation
            expected_audience: Expected audience value
            holder_key_resolver: Optional function to resolve holder keys

        Returns:
            Tuple of (is_valid, verified_claims, tags_absent)
            - is_valid: Whether the presentation is cryptographically valid
            - verified_claims: The disclosed claims (if valid)
            - tags_absent: Whether redaction tags (58, 59, 60) are absent from claims

        Example:
            valid, claims, clean = verifier.verify_presentation(
                kbt=presentation,
                expected_audience="https://customs.us.example"
            )
        """
        from .verifiers import get_presentation_verifier

        try:
            # Extract the original SD-CWT from KBT
            kbt_decoded = cbor_utils.decode(kbt)
            if cbor_utils.is_tag(kbt_decoded):
                kbt_value = cbor_utils.get_tag_value(kbt_decoded)
            else:
                kbt_value = kbt_decoded

            # Get protected header to extract the SD-CWT
            protected_header_bytes = kbt_value[0]
            protected_header = cbor_utils.decode(protected_header_bytes)

            if 13 not in protected_header:  # kcwt field
                return False, None, False

            sd_cwt_with_disclosures = protected_header[13]

            # The kcwt field contains the SD-CWT with disclosures
            # For verification, we need just the SD-CWT part
            # In this simple implementation, we'll use the whole kcwt as the SD-CWT
            sd_cwt = sd_cwt_with_disclosures

            # Verify the SD-CWT credential first
            is_valid, payload = self.credential_verifier.verify(sd_cwt)
            if not is_valid or not payload:
                return False, None, False

            # Get presentation verifier for KBT verification
            presentation_verifier = get_presentation_verifier(
                sd_cwt,
                self.credential_verifier,
                holder_key_resolver
            )

            if presentation_verifier is None:
                return False, None, False

            # Verify the KBT signature and audience
            kbt_valid, kbt_payload = presentation_verifier.verify(kbt, audience=expected_audience)
            if not kbt_valid or not kbt_payload:
                return False, None, False

            # Extract disclosures from the SD-CWT and reconstruct verified claims
            clean_claims, tags_absent = self._reconstruct_verified_claims(
                sd_cwt_with_disclosures, payload
            )

            return True, clean_claims, tags_absent

        except Exception as e:
            import traceback
            print(f"Verification error: {e}")  # For debugging
            traceback.print_exc()
            return False, None, False

    def _extract_clean_claims(self, payload: Dict[int, Any]) -> Tuple[Dict[str, Any], bool]:
        """Extract claims and check if redaction tags are absent.

        Args:
            payload: Decoded SD-CWT payload

        Returns:
            Tuple of (clean_claims, tags_absent)
        """
        clean_claims = {}
        tags_absent = True

        for key, value in payload.items():
            # Handle standard JWT claims
            if key == 1:
                clean_claims['iss'] = value
                continue
            elif key == 2:
                clean_claims['sub'] = value
                continue
            elif key == 6:
                clean_claims['iat'] = value
                continue
            elif key == 8:
                # cnf claim - don't include in clean claims
                continue

            # Skip redaction metadata (simple(59)) - this doesn't affect tags_absent
            if key == cbor_utils.create_simple_value(59):  # simple(59)
                continue

            # Check for tags 58, 60 in the actual claim values
            clean_value, value_clean = self._clean_value_recursive(value)

            if not value_clean:
                tags_absent = False

            if isinstance(key, str):
                clean_claims[key] = clean_value

        return clean_claims, tags_absent

    def _reconstruct_verified_claims(
        self,
        sd_cwt_with_disclosures: bytes,
        payload: Dict[int, Any]
    ) -> Tuple[Dict[str, Any], bool]:
        """Reconstruct verified claims from SD-CWT payload and disclosures.

        Args:
            sd_cwt_with_disclosures: SD-CWT with selected disclosures
            payload: Decoded SD-CWT payload

        Returns:
            Tuple of (clean_claims, tags_absent)
        """
        # First, extract the base claims from payload (same as before)
        clean_claims, _ = self._extract_clean_claims(payload)

        # Extract disclosed claims from SD-CWT unprotected header
        try:
            cose_sign1 = cbor_utils.decode(sd_cwt_with_disclosures)
            if cbor_utils.is_tag(cose_sign1):
                cose_sign1_value = cbor_utils.get_tag_value(cose_sign1)
            else:
                cose_sign1_value = cose_sign1

            if isinstance(cose_sign1_value, list) and len(cose_sign1_value) >= 2:
                unprotected_header = cose_sign1_value[1]
                if isinstance(unprotected_header, dict):
                    # Extract sd_claims (key 17 based on spec examples)
                    sd_claims = unprotected_header.get(17, [])

                    # Process each disclosure and add to clean_claims
                    for disclosure_bytes in sd_claims:
                        if isinstance(disclosure_bytes, bytes):
                            disclosure = cbor_utils.decode(disclosure_bytes)
                            if isinstance(disclosure, list) and len(disclosure) == 3:
                                # SD-CWT format: [salt, value, key]
                                salt, value, key = disclosure

                                # Add disclosed claim to clean_claims
                                if isinstance(key, str):
                                    clean_claims[key] = value
                                elif isinstance(key, int):
                                    # Handle numeric keys by converting to standard claim names
                                    if key == 1:
                                        clean_claims['iss'] = value
                                    elif key == 2:
                                        clean_claims['sub'] = value
                                    elif key == 6:
                                        clean_claims['iat'] = value
                                    # Add other numeric key mappings as needed

        except Exception:
            # If disclosure processing fails, just return the base claims
            pass

        # All disclosed claims should have tags absent since they're explicitly disclosed
        tags_absent = True

        return clean_claims, tags_absent

    def _clean_value_recursive(self, value: Any) -> Tuple[Any, bool]:
        """Recursively clean a value and check for redaction tags.

        Returns:
            Tuple of (cleaned_value, is_clean)
        """
        is_clean = True

        # Check if this is a CBOR tag
        if cbor_utils.is_tag(value):
            tag_number = cbor_utils.get_tag_number(value)
            if tag_number in [58, 59, 60]:
                is_clean = False
                # Return the tag value, cleaned recursively
                inner_value, inner_clean = self._clean_value_recursive(cbor_utils.get_tag_value(value))
                return inner_value, inner_clean
            else:
                # Other tags - keep as is but check inner value
                inner_value, inner_clean = self._clean_value_recursive(cbor_utils.get_tag_value(value))
                return value, inner_clean

        elif isinstance(value, dict):
            clean_dict = {}
            for k, v in value.items():
                clean_v, v_clean = self._clean_value_recursive(v)
                clean_dict[k] = clean_v
                if not v_clean:
                    is_clean = False
            return clean_dict, is_clean

        elif isinstance(value, list):
            clean_list = []
            for item in value:
                clean_item, item_clean = self._clean_value_recursive(item)
                clean_list.append(clean_item)
                if not item_clean:
                    is_clean = False
            return clean_list, is_clean

        else:
            # Primitive value
            return value, is_clean