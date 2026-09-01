from . import cbor_utils

"""Unfinished EDN-driven SD-CWT issuer prototype.

NOT the issuer to use. `sd_cwt.SDCWTIssuer` (in `simple_api`) is the working
one; this module is an earlier sketch that shares its class name but never
gained real signing. It is deliberately not exported from `sd_cwt/__init__.py`.

`create_sd_cwt` raises rather than returning a token, because it previously
returned a COSE_Sign1 carrying a literal placeholder in the signature slot, and
an unsigned token that looks signed is worse than no token at all.
"""

import secrets
from typing import Any, Optional

from fido2.cose import CoseKey

from . import edn_utils
from .redaction import hash_disclosure as redaction_hash_disclosure


class SDCWTIssuer:
    """SD-CWT issuer that creates selective disclosure tokens using EDN."""

    # CBOR tags for redaction (from latest spec)
    REDACTED_CLAIM_KEY_TAG = 58  # TBD3 - tag for to-be-redacted keys
    REDACTED_CLAIM_ELEMENT_TAG = 58  # TBD3 - tag for to-be-redacted array elements

    def __init__(self, signing_key: CoseKey, issuer: str):
        """Initialize SD-CWT issuer.

        Args:
            signing_key: COSE key for signing SD-CWTs
            issuer: Issuer identifier (iss claim)
        """
        self.signing_key = signing_key
        self.issuer = issuer
        self.hash_alg = "sha-256"  # Default hash algorithm

    def parse_edn_claims(self, edn_claims: str) -> tuple[dict[Any, Any], list[str]]:
        """Parse EDN claims and identify redaction tags.

        Args:
            edn_claims: Claims in EDN format with redaction tags

        Returns:
            Tuple of (claims_dict, redacted_claim_names)
        """
        # Parse the EDN to CBOR
        cbor_data = edn_utils.diag_to_cbor(edn_claims)
        claims = cbor_utils.decode(cbor_data)

        redacted_claims = []

        # Look for redaction tags in the parsed structure
        def find_redacted_claims(obj: Any, path: str = "") -> None:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else str(key)

                    # Check if this is a redacted claim key (tag 59)
                    if (
                        hasattr(value, "tag")
                        and cbor_utils.get_tag_number(value) == self.REDACTED_CLAIM_KEY_TAG
                        or hasattr(value, "tag")
                        and cbor_utils.get_tag_number(value) == self.REDACTED_CLAIM_ELEMENT_TAG
                    ):
                        redacted_claims.append(key)

                    # Recursively check nested structures
                    elif isinstance(value, (dict, list)):
                        find_redacted_claims(value, current_path)

            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]" if path else f"[{i}]"
                    if isinstance(item, (dict, list)):
                        find_redacted_claims(item, current_path)

        find_redacted_claims(claims)

        return claims, redacted_claims

    def create_disclosure(self, salt: bytes, claim_name: str, claim_value: Any) -> bytes:
        """Create a disclosure for a claim.

        Args:
            salt: 128-bit cryptographically random salt
            claim_name: Name of the claim
            claim_value: Value of the claim

        Returns:
            CBOR-encoded disclosure array [salt, value, key] (SD-CWT format)
        """
        # SD-CWT format: [salt, value, key] (different from SD-JWT [salt, key, value])
        disclosure_array = [salt, claim_value, claim_name]
        return cbor_utils.encode(disclosure_array)

    def hash_disclosure(self, disclosure: bytes) -> bytes:
        """Compute the Redacted Claim Hash of a disclosure.

        Delegates to `redaction.hash_disclosure` so there is one definition of
        the digest. This used to hash the bare `salted-entry` array encoding,
        while the CDDL defines the input as `bstr .cbor salted-entry`, producing
        digests no other implementation could match.

        Args:
            disclosure: CBOR-encoded salted-entry (the bstr contents)

        Returns:
            Hash of the disclosure
        """
        return redaction_hash_disclosure(disclosure, self.hash_alg)

    def create_sd_cwt(
        self, edn_claims: str, holder_key: Optional[CoseKey] = None
    ) -> dict[str, Any]:
        """Create an SD-CWT from EDN claims with redaction tags.

        Args:
            edn_claims: Claims in EDN format with redaction tags
            holder_key: Optional COSE key for holder binding

        Returns:
            Dictionary containing:
            - sd_cwt: The signed SD-CWT token (bytes)
            - disclosures: List of disclosure arrays (bytes)
            - holder_key: Holder key if provided
        """
        # Parse EDN claims and find redacted claims
        all_claims, redacted_claim_names = self.parse_edn_claims(edn_claims)

        # Create disclosures for redacted claims
        disclosures = []
        sd_hashes = []

        for claim_name in redacted_claim_names:
            if claim_name in all_claims:
                # Generate 128-bit random salt
                salt = secrets.token_bytes(16)

                # Create disclosure
                claim_value = all_claims[claim_name]
                disclosure = self.create_disclosure(salt, claim_name, claim_value)
                disclosures.append(disclosure)

                # Hash the disclosure
                hash_digest = self.hash_disclosure(disclosure)
                sd_hashes.append(hash_digest)

                # Remove the claim from the main claims
                del all_claims[claim_name]

        # Create SD-CWT claims
        sd_cwt_claims = all_claims.copy()
        # Use CBOR simple value 59 for redacted claim keys (not "_sd")
        if sd_hashes:
            sd_cwt_claims[59] = sd_hashes  # simple(59) for redacted_claim_keys

        # Add holder binding if provided
        if holder_key:
            cnf_claim = {1: holder_key}  # COSE_Key
            sd_cwt_claims[8] = cnf_claim  # cnf claim

        # Create COSE_Sign1 structure
        # Protected header with algorithm
        protected_header = {
            1: -7,  # ES256 algorithm
        }
        protected_header_cbor = cbor_utils.encode(protected_header)

        # Payload (SD-CWT claims)
        payload = cbor_utils.encode(sd_cwt_claims)

        # Create signing input: Sig_structure for COSE_Sign1
        sig_structure = [
            "Signature1",  # Context
            protected_header_cbor,  # Protected header
            b"",  # External AAD (empty)
            payload,  # Payload
        ]

        cbor_utils.encode(sig_structure)  # what a real signer would sign

        raise NotImplementedError(
            "sd_cwt.issuer.SDCWTIssuer cannot sign. It previously returned a "
            "COSE_Sign1 whose signature was the literal bytes "
            "b'dummy_signature_placeholder', which no verifier accepts and which "
            "is indistinguishable from a real token to a caller that does not "
            "check. Use sd_cwt.SDCWTIssuer from sd_cwt.simple_api instead."
        )

    def create_presentation(
        self, sd_cwt: bytes, disclosures: list[bytes], selected_disclosures: list[int]
    ) -> dict[str, Any]:
        """Create an SD-CWT presentation with selected disclosures.

        Args:
            sd_cwt: The SD-CWT token
            disclosures: All available disclosures
            selected_disclosures: Indices of disclosures to include

        Returns:
            SD-CWT presentation dictionary
        """
        selected_disclosure_bytes = [disclosures[i] for i in selected_disclosures]

        return {"sd_cwt": sd_cwt, "disclosures": selected_disclosure_bytes}

    def to_edn(self, data: Any) -> str:
        """Convert data to CBOR Extended Diagnostic Notation.

        Args:
            data: Data to convert

        Returns:
            EDN representation
        """
        cbor_data = cbor_utils.encode(data)
        return edn_utils.cbor_to_diag(cbor_data)


def create_example_edn_claims() -> str:
    """Create example EDN claims matching the specification.

    Returns:
        EDN claims string with redaction tags
    """
    # Based on the specification example
    edn_claims = """
    {
        1: "https://issuer.example",
        2: "https://holder.example",
        4: 1725330600,
        5: 1725243840,
        6: 1725244200,
        8: {
            1: {
                1: 2,
                -1: 1,
                -2: h'8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d',
                -3: h'4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'
            }
        },
        500: 59(true),  / Redacted claim key tag /
        501: "ABCD-123456",
        502: 60([1549560720, 1612498440, 1674004740]),  / Redacted claim element tag /
        503: {
            "country": "us",
            "region": "ca",
            "postal_code": "94188"
        }
    }
    """

    return edn_claims.strip()
