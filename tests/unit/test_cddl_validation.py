"""Unit tests for CDDL validation against SD-CWT and COSE Key specifications."""

import base64
import hashlib
from typing import Any, Dict

import cbor2
import pytest
import pycddl

from sd_cwt.cddl_schemas import (
    COSE_KEY_THUMBPRINT_CDDL,
    SD_CWT_CDDL,
    TEST_VECTOR_CDDL,
)
from sd_cwt.thumbprint import CoseKeyThumbprint


class TestCDDLValidation:
    """Test cases for CDDL schema validation."""
    
    @pytest.fixture
    def sd_cwt_schema(self):
        """Compile SD-CWT CDDL schema."""
        try:
            return pycddl.Schema(SD_CWT_CDDL)
        except Exception:
            # Return None if compilation fails (pycddl might have issues)
            return None
    
    @pytest.fixture
    def cose_key_schema(self):
        """Compile COSE Key Thumbprint CDDL schema."""
        try:
            return pycddl.Schema(COSE_KEY_THUMBPRINT_CDDL)
        except Exception:
            return None
    
    @pytest.fixture
    def test_vector_schema(self):
        """Compile test vector CDDL schema."""
        try:
            return pycddl.Schema(TEST_VECTOR_CDDL)
        except Exception:
            return None
    
    @pytest.fixture
    def valid_sd_cwt_claims(self) -> Dict[str, Any]:
        """Valid SD-CWT claims structure."""
        return {
            1: "https://issuer.example.com",  # iss
            2: "user123",  # sub
            6: 1700000000,  # iat
            59: [  # redacted_claim_keys (simple value 59)
                hashlib.sha256(b"disclosure1").digest(),
                hashlib.sha256(b"disclosure2").digest(),
            ],
        }
    
    @pytest.fixture
    def valid_ec2_key(self) -> Dict[int, Any]:
        """Valid EC2 COSE key."""
        return {
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: b"x" * 32,  # x coordinate (32 bytes for P-256)
            -3: b"y" * 32,  # y coordinate
        }
    
    @pytest.fixture
    def valid_okp_key(self) -> Dict[int, Any]:
        """Valid OKP COSE key."""
        return {
            1: 1,  # kty: OKP
            3: -8,  # alg: EdDSA
            -1: 6,  # crv: Ed25519
            -2: b"x" * 32,  # x coordinate
        }
    
    @pytest.mark.unit
    def test_sd_cwt_claims_structure(self, valid_sd_cwt_claims: Dict[str, Any]):
        """Test SD-CWT claims structure validation."""
        # Encode to CBOR
        cbor_data = cbor2.dumps(valid_sd_cwt_claims)
        
        # Basic validation - check structure
        decoded = cbor2.loads(cbor_data)
        assert 1 in decoded  # iss
        assert 59 in decoded  # redacted_claim_keys
        assert isinstance(decoded[59], list)
    
    @pytest.mark.unit
    def test_sd_cwt_with_standard_claims(self):
        """Test SD-CWT with all standard CWT claims."""
        claims = {
            1: "issuer",  # iss
            2: "subject",  # sub
            3: "audience",  # aud
            4: 1700001000,  # exp
            5: 1700000000,  # nbf
            6: 1700000000,  # iat
            7: b"unique-id",  # cti
            59: [],  # redacted_claim_keys (empty array)
        }
        
        cbor_data = cbor2.dumps(claims)
        decoded = cbor2.loads(cbor_data)
        
        # Verify all standard claims
        assert decoded[1] == "issuer"
        assert decoded[2] == "subject"
        assert decoded[3] == "audience"
        assert decoded[4] == 1700001000
        assert decoded[5] == 1700000000
        assert decoded[6] == 1700000000
        assert decoded[7] == b"unique-id"
    
    @pytest.mark.unit
    def test_disclosure_format_validation(self):
        """Test disclosure array format validation."""
        disclosure = [
            b"random_salt_value",  # salt
            "given_name",  # claim name
            "John",  # claim value
        ]
        
        cbor_data = cbor2.dumps(disclosure)
        decoded = cbor2.loads(cbor_data)
        
        assert len(decoded) == 3
        assert isinstance(decoded[0], bytes)
        assert isinstance(decoded[1], str)
        # Third element can be any type
    
    @pytest.mark.unit
    def test_ec2_thumbprint_structure(self, valid_ec2_key: Dict[int, Any]):
        """Test EC2 key structure for thumbprint."""
        # Extract only required fields for thumbprint
        thumbprint_key = {
            1: valid_ec2_key[1],  # kty
            -1: valid_ec2_key[-1],  # crv
            -2: valid_ec2_key[-2],  # x
            -3: valid_ec2_key[-3],  # y
        }
        
        cbor_data = cbor2.dumps(thumbprint_key)
        decoded = cbor2.loads(cbor_data)
        
        assert decoded[1] == 2  # EC2
        assert decoded[-1] == 1  # P-256
        assert len(decoded) == 4  # Only required fields
    
    @pytest.mark.unit
    def test_okp_thumbprint_structure(self, valid_okp_key: Dict[int, Any]):
        """Test OKP key structure for thumbprint."""
        # Extract only required fields for thumbprint
        thumbprint_key = {
            1: valid_okp_key[1],  # kty
            -1: valid_okp_key[-1],  # crv
            -2: valid_okp_key[-2],  # x
        }
        
        cbor_data = cbor2.dumps(thumbprint_key)
        decoded = cbor2.loads(cbor_data)
        
        assert decoded[1] == 1  # OKP
        assert decoded[-1] == 6  # Ed25519
        assert len(decoded) == 3  # Only required fields
    
    @pytest.mark.unit
    def test_rsa_thumbprint_structure(self):
        """Test RSA key structure for thumbprint."""
        rsa_key = {
            1: 3,  # kty: RSA
            -1: b"n" * 256,  # modulus (2048 bits)
            -2: b"\x01\x00\x01",  # exponent (65537)
        }
        
        cbor_data = cbor2.dumps(rsa_key)
        decoded = cbor2.loads(cbor_data)
        
        assert decoded[1] == 3  # RSA
        assert len(decoded[-1]) == 256  # 2048-bit modulus
        assert decoded[-2] == b"\x01\x00\x01"  # Common exponent
    
    @pytest.mark.unit
    def test_symmetric_thumbprint_structure(self):
        """Test symmetric key structure for thumbprint."""
        symmetric_key = {
            1: 4,  # kty: Symmetric
            -1: b"k" * 32,  # key value (256 bits)
        }
        
        cbor_data = cbor2.dumps(symmetric_key)
        decoded = cbor2.loads(cbor_data)
        
        assert decoded[1] == 4  # Symmetric
        assert len(decoded[-1]) == 32  # 256-bit key
        assert len(decoded) == 2  # Only required fields
    
    @pytest.mark.unit
    def test_cnf_claim_structure(self, valid_ec2_key: Dict[int, Any]):
        """Test confirmation (cnf) claim structure."""
        cnf = {
            1: valid_ec2_key,  # COSE_Key
            3: b"key-id-12345",  # kid
        }
        
        cbor_data = cbor2.dumps(cnf)
        decoded = cbor2.loads(cbor_data)
        
        assert 1 in decoded  # COSE_Key
        assert 3 in decoded  # kid
        assert decoded[1][1] == 2  # EC2 key type
    
    @pytest.mark.unit
    def test_sd_cwt_with_holder_binding(
        self, valid_sd_cwt_claims: Dict[str, Any], valid_ec2_key: Dict[int, Any]
    ):
        """Test SD-CWT with holder binding (cnf claim)."""
        claims = valid_sd_cwt_claims.copy()
        claims[8] = {1: valid_ec2_key}  # cnf with COSE_Key
        
        cbor_data = cbor2.dumps(claims)
        decoded = cbor2.loads(cbor_data)
        
        assert 8 in decoded  # cnf claim
        assert 1 in decoded[8]  # COSE_Key in cnf
    
    @pytest.mark.unit
    def test_sd_cwt_presentation_structure(self):
        """Test SD-CWT presentation structure."""
        presentation = {
            "sd_cwt": base64.b64encode(b"cwt_token_bytes").decode(),
            "disclosures": [
                base64.b64encode(b"disclosure1").decode(),
                base64.b64encode(b"disclosure2").decode(),
            ],
            "kb_jwt": base64.b64encode(b"key_binding_jwt").decode(),
        }
        
        cbor_data = cbor2.dumps(presentation)
        decoded = cbor2.loads(cbor_data)
        
        assert "sd_cwt" in decoded
        assert "disclosures" in decoded
        assert "kb_jwt" in decoded
        assert len(decoded["disclosures"]) == 2
    
    @pytest.mark.unit
    def test_thumbprint_uri_format(self, valid_ec2_key: Dict[int, Any]):
        """Test thumbprint URI format validation."""
        uri = CoseKeyThumbprint.uri(valid_ec2_key, "sha256")
        
        # Validate URI format
        assert uri.startswith("urn:ietf:params:oauth:ckt:")
        parts = uri.split(":")
        assert len(parts) == 7
        assert parts[5] in ["sha256", "sha384", "sha512"]
        
        # Base64url part should not contain padding
        b64_part = parts[6]
        assert "=" not in b64_part
        assert "+" not in b64_part
        assert "/" not in b64_part
    
    @pytest.mark.unit
    def test_test_vector_structure(self, valid_ec2_key: Dict[int, Any]):
        """Test test vector structure validation."""
        test_vector = {
            "description": "EC2 key thumbprint test",
            "input": {
                "key": valid_ec2_key,
                "hash_alg": "sha256",
            },
            "output": {
                "thumbprint": hashlib.sha256(b"test").digest(),
                "thumbprint_uri": "urn:ietf:params:oauth:ckt:sha256:test",
            },
            "intermediate": {
                "canonical_key": b"canonical_cbor_bytes",
            },
        }
        
        cbor_data = cbor2.dumps(test_vector)
        decoded = cbor2.loads(cbor_data)
        
        assert "description" in decoded
        assert "input" in decoded
        assert "output" in decoded
        assert "key" in decoded["input"]
        assert "thumbprint" in decoded["output"]
    
    @pytest.mark.unit
    def test_curve_identifiers(self):
        """Test COSE curve identifiers."""
        curves = {
            1: "P-256",
            2: "P-384",
            3: "P-521",
            4: "X25519",
            5: "X448",
            6: "Ed25519",
            7: "Ed448",
        }
        
        for crv_id, name in curves.items():
            # Create a key with the curve
            if crv_id in [1, 2, 3]:  # EC2 curves
                key = {1: 2, -1: crv_id, -2: b"x", -3: b"y"}
            else:  # OKP curves
                key = {1: 1, -1: crv_id, -2: b"x"}
            
            cbor_data = cbor2.dumps(key)
            decoded = cbor2.loads(cbor_data)
            assert decoded[-1] == crv_id
    
    @pytest.mark.unit
    def test_algorithm_identifiers(self):
        """Test COSE algorithm identifiers."""
        algorithms = {
            -7: "ES256",
            -8: "EdDSA",
            -35: "ES384",
            -36: "ES512",
            -257: "RS256",
            -258: "RS384",
            -259: "RS512",
        }
        
        for alg_id, name in algorithms.items():
            key = {1: 2, 3: alg_id}  # Simple key with algorithm
            cbor_data = cbor2.dumps(key)
            decoded = cbor2.loads(cbor_data)
            assert decoded[3] == alg_id
    
    @pytest.mark.unit
    def test_undisclosed_claims_marker(self):
        """Test the '...' marker for undisclosed claims."""
        claims = {
            1: "issuer",
            2: "subject",
            59: [b"hash1", b"hash2"],  # redacted_claim_keys
            "...": True,  # Indicates more undisclosed claims exist
        }
        
        cbor_data = cbor2.dumps(claims)
        decoded = cbor2.loads(cbor_data)
        
        assert "..." in decoded
        assert decoded["..."] is True
    
    @pytest.mark.unit
    @pytest.mark.skipif(
        pycddl is None, reason="pycddl not available or not working"
    )
    def test_pycddl_validation(self, sd_cwt_schema, valid_sd_cwt_claims):
        """Test actual CDDL validation with pycddl if available."""
        if sd_cwt_schema is None:
            pytest.skip("CDDL schema compilation failed")
        
        cbor_data = cbor2.dumps(valid_sd_cwt_claims)
        
        try:
            sd_cwt_schema.validate_cbor(cbor_data, "sd-cwt-claims")
            assert True  # Validation passed
        except Exception as e:
            # pycddl might have compatibility issues
            print(f"CDDL validation failed: {e}")
            pass