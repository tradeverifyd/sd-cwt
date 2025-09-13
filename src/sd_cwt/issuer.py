"""SD-CWT Issuer implementation using EDN with redaction tags.

This module implements SD-CWT (Selective Disclosure CBOR Web Token) issuance
according to the latest draft specification from IETF SPICE Working Group.
It uses CBOR Extended Diagnostic Notation (EDN) with redaction tags to
specify which claims should be selectively disclosed.
"""

import hashlib
import secrets
from typing import Any, Dict, List, Optional, Tuple, Union

import cbor2
import cbor_diag
from fido2.cose import CoseKey, ES256

from .cddl_schemas import SD_CWT_CDDL
from .thumbprint import CoseKeyThumbprint


class SDCWTIssuer:
    """SD-CWT issuer that creates selective disclosure tokens using EDN."""
    
    # CBOR tags for redaction (from latest spec)
    REDACTED_CLAIM_KEY_TAG = 59      # TBD4 - requested value 59
    REDACTED_CLAIM_ELEMENT_TAG = 60  # Tag 60
    
    def __init__(self, signing_key: CoseKey, issuer: str):
        """Initialize SD-CWT issuer.
        
        Args:
            signing_key: COSE key for signing SD-CWTs
            issuer: Issuer identifier (iss claim)
        """
        self.signing_key = signing_key
        self.issuer = issuer
        self.hash_alg = "sha-256"  # Default hash algorithm
    
    def parse_edn_claims(self, edn_claims: str) -> Tuple[Dict[Any, Any], List[str]]:
        """Parse EDN claims and identify redaction tags.
        
        Args:
            edn_claims: Claims in EDN format with redaction tags
            
        Returns:
            Tuple of (claims_dict, redacted_claim_names)
        """
        # Parse the EDN to CBOR
        cbor_data = cbor_diag.diag2cbor(edn_claims)
        claims = cbor2.loads(cbor_data)
        
        redacted_claims = []
        
        # Look for redaction tags in the parsed structure
        def find_redacted_claims(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else str(key)
                    
                    # Check if this is a redacted claim key (tag 59)
                    if hasattr(value, 'tag') and value.tag == self.REDACTED_CLAIM_KEY_TAG:
                        redacted_claims.append(key)
                    
                    # Check if this is a redacted claim element (tag 60)
                    elif hasattr(value, 'tag') and value.tag == self.REDACTED_CLAIM_ELEMENT_TAG:
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
        return cbor2.dumps(disclosure_array)
    
    def hash_disclosure(self, disclosure: bytes) -> bytes:
        """Hash a disclosure using the configured hash algorithm.
        
        Args:
            disclosure: CBOR-encoded disclosure
            
        Returns:
            Hash of the disclosure
        """
        if self.hash_alg == "sha-256":
            return hashlib.sha256(disclosure).digest()
        elif self.hash_alg == "sha-384":
            return hashlib.sha384(disclosure).digest()
        elif self.hash_alg == "sha-512":
            return hashlib.sha512(disclosure).digest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {self.hash_alg}")
    
    def create_sd_cwt(self, edn_claims: str, holder_key: Optional[CoseKey] = None) -> Dict[str, Any]:
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
            cnf_claim = {
                1: holder_key  # COSE_Key
            }
            sd_cwt_claims[8] = cnf_claim  # cnf claim
        
        # Create COSE_Sign1 structure
        # Protected header with algorithm
        protected_header = {
            1: -7,  # ES256 algorithm
        }
        protected_header_cbor = cbor2.dumps(protected_header)
        
        # Unprotected header (empty)
        unprotected_header = {}
        
        # Payload (SD-CWT claims)
        payload = cbor2.dumps(sd_cwt_claims)
        
        # Create signing input: Sig_structure for COSE_Sign1
        sig_structure = [
            "Signature1",  # Context
            protected_header_cbor,  # Protected header
            b"",  # External AAD (empty)
            payload  # Payload
        ]
        
        tbs = cbor2.dumps(sig_structure)
        
        # Sign with ES256 (placeholder - would use actual signing)
        # For now, create a dummy signature
        signature = b"dummy_signature_placeholder" + b"\x00" * 37  # 64 bytes total
        
        # Create COSE_Sign1 array
        cose_sign1 = [
            protected_header_cbor,
            unprotected_header,
            payload,
            signature
        ]
        
        # Encode as CBOR with tag 18 (COSE_Sign1)
        sd_cwt = cbor2.dumps(cbor2.CBORTag(18, cose_sign1))
        
        return {
            "sd_cwt": sd_cwt,
            "disclosures": disclosures,
            "holder_key": holder_key
        }
    
    def create_presentation(self, sd_cwt: bytes, disclosures: List[bytes], 
                          selected_disclosures: List[int]) -> Dict[str, Any]:
        """Create an SD-CWT presentation with selected disclosures.
        
        Args:
            sd_cwt: The SD-CWT token
            disclosures: All available disclosures
            selected_disclosures: Indices of disclosures to include
            
        Returns:
            SD-CWT presentation dictionary
        """
        selected_disclosure_bytes = [disclosures[i] for i in selected_disclosures]
        
        return {
            "sd_cwt": sd_cwt,
            "disclosures": selected_disclosure_bytes
        }
    
    def to_edn(self, data: Any) -> str:
        """Convert data to CBOR Extended Diagnostic Notation.
        
        Args:
            data: Data to convert
            
        Returns:
            EDN representation
        """
        cbor_data = cbor2.dumps(data)
        return cbor_diag.cbor2diag(cbor_data)


def create_example_edn_claims() -> str:
    """Create example EDN claims matching the specification.
    
    Returns:
        EDN claims string with redaction tags
    """
    # Based on the specification example
    edn_claims = '''
    {
        1: "https://issuer.example",
        2: "https://device.example",
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
    '''
    
    return edn_claims.strip()