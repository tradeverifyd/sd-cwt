"""Comprehensive unit tests for keys from Appendix C of draft-ietf-spice-sd-cwt-latest.txt"""

import pytest

from sd_cwt import cbor_utils, edn_utils
from sd_cwt.thumbprint import CoseKeyThumbprint


class TestAppendixCKeys:
    """Test key examples from Appendix C: Keys Used in the Examples."""

    @pytest.fixture
    def es256_holder_private_key_edn(self):
        """ES256 Holder/Subject private key from C.1 (with corrected algorithm)."""
        return """
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: h'8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d',
            -3: h'4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343',
            -4: h'5759a86e59bb3b002dde467da4b52f3d06e6c2cd439456cf0485b9b864294ce5'
        }
        """

    @pytest.fixture
    def es256_holder_public_key_edn(self):
        """ES256 Holder public key for thumbprint computation (without private component)."""
        return """
        {
            1: 2,
            -1: 1,
            -2: h'8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d',
            -3: h'4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'
        }
        """

    @pytest.fixture
    def es384_issuer_private_key_edn(self):
        """ES384 Issuer private key from C.2 (with corrected algorithm)."""
        return """
        {
            1: 2,
            2: "https://issuer.example/cwk3.cbor",
            3: -35,
            -1: 2,
            -2: h'c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf',
            -3: h'8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e84a055a31fb7f9214b27509522c159e764f8711e11609554',
            -4: h'71c54d2221937ea612db1221f0d3ddf771c9381c4e3be41d5aa0a89d685f09cfef74c4bbf104783fd57e87ab227d074c'
        }
        """

    @pytest.fixture
    def es384_issuer_public_key_edn(self):
        """ES384 Issuer public key for thumbprint computation (without private component and kid)."""
        return """
        {
            1: 2,
            -1: 2,
            -2: h'c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf',
            -3: h'8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e84a055a31fb7f9214b27509522c159e764f8711e11609554'
        }
        """

    def test_es256_holder_private_key_structure(self, es256_holder_private_key_edn):
        """Test ES256 holder private key structure and values from specification C.1."""
        cbor_data = edn_utils.diag_to_cbor(es256_holder_private_key_edn)
        key = cbor_utils.decode(cbor_data)

        assert isinstance(key, dict)
        assert key[1] == 2    # kty: EC2
        assert key[3] == -7   # alg: ES256 (corrected from spec's erroneous -9)
        assert key[-1] == 1   # crv: P-256

        assert len(key[-2]) == 32  # X coordinate: 32 bytes for P-256
        assert len(key[-3]) == 32  # Y coordinate: 32 bytes for P-256
        assert len(key[-4]) == 32  # Private key: 32 bytes for P-256

        expected_x = bytes.fromhex('8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d')
        expected_y = bytes.fromhex('4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343')
        expected_d = bytes.fromhex('5759a86e59bb3b002dde467da4b52f3d06e6c2cd439456cf0485b9b864294ce5')

        assert key[-2] == expected_x
        assert key[-3] == expected_y
        assert key[-4] == expected_d

    def test_es256_holder_public_key_structure(self, es256_holder_public_key_edn):
        """Test ES256 holder public key structure for thumbprint computation."""
        cbor_data = edn_utils.diag_to_cbor(es256_holder_public_key_edn)
        key = cbor_utils.decode(cbor_data)

        assert isinstance(key, dict)
        assert len(key) == 4  # Should only have 4 fields (no private key, no alg)
        assert -4 not in key  # No private key component
        assert 3 not in key   # No alg in thumbprint format
        assert key[1] == 2    # kty: EC2
        assert key[-1] == 1   # crv: P-256

    def test_es384_issuer_private_key_structure(self, es384_issuer_private_key_edn):
        """Test ES384 issuer private key structure and values from specification C.2."""
        cbor_data = edn_utils.diag_to_cbor(es384_issuer_private_key_edn)
        key = cbor_utils.decode(cbor_data)

        assert isinstance(key, dict)
        assert key[1] == 2    # kty: EC2
        assert key[2] == "https://issuer.example/cwk3.cbor"  # kid
        assert key[3] == -35  # alg: ES384 (corrected from spec's erroneous -51)
        assert key[-1] == 2   # crv: P-384

        assert len(key[-2]) == 48  # X coordinate: 48 bytes for P-384
        assert len(key[-3]) == 48  # Y coordinate: 48 bytes for P-384
        assert len(key[-4]) == 48  # Private key: 48 bytes for P-384

        expected_x = bytes.fromhex('c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf')
        expected_y = bytes.fromhex('8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e84a055a31fb7f9214b27509522c159e764f8711e11609554')
        expected_d = bytes.fromhex('71c54d2221937ea612db1221f0d3ddf771c9381c4e3be41d5aa0a89d685f09cfef74c4bbf104783fd57e87ab227d074c')

        assert key[-2] == expected_x
        assert key[-3] == expected_y
        assert key[-4] == expected_d

    def test_es384_issuer_public_key_structure(self, es384_issuer_public_key_edn):
        """Test ES384 issuer public key structure for thumbprint computation."""
        cbor_data = edn_utils.diag_to_cbor(es384_issuer_public_key_edn)
        key = cbor_utils.decode(cbor_data)

        assert isinstance(key, dict)
        assert len(key) == 4  # Should only have 4 fields (no kid, no alg, no private key)
        assert -4 not in key  # No private key component
        assert 2 not in key   # No kid in thumbprint format
        assert 3 not in key   # No alg in thumbprint format
        assert key[1] == 2    # kty: EC2
        assert key[-1] == 2   # crv: P-384

    def test_thumbprint_computation_es256_holder(self, es256_holder_public_key_edn):
        """Test COSE key thumbprint computation for ES256 holder key matches specification."""
        cbor_data = edn_utils.diag_to_cbor(es256_holder_public_key_edn)
        key = cbor_utils.decode(cbor_data)

        thumbprint = CoseKeyThumbprint.compute(key, "sha256")
        expected_thumbprint = bytes.fromhex('8343d73cdfcb81f2c7cd11a5f317be8eb34e4807ec8c9ceb282495cffdf037e0')

        assert thumbprint == expected_thumbprint, f"Expected {expected_thumbprint.hex()}, got {thumbprint.hex()}"

    def test_thumbprint_computation_es384_issuer(self, es384_issuer_public_key_edn):
        """Test COSE key thumbprint computation for ES384 issuer key matches specification."""
        cbor_data = edn_utils.diag_to_cbor(es384_issuer_public_key_edn)
        key = cbor_utils.decode(cbor_data)

        thumbprint = CoseKeyThumbprint.compute(key, "sha256")
        expected_thumbprint = bytes.fromhex('554550a611c9807b3462cfec4a690a1119bc43b571da1219782133f5fd6dbcb0')

        assert thumbprint == expected_thumbprint, f"Expected {expected_thumbprint.hex()}, got {thumbprint.hex()}"

    def test_cbor_roundtrip_all_keys(self, es256_holder_private_key_edn, es384_issuer_private_key_edn):
        """Test CBOR encoding/decoding roundtrip for all keys from specification."""
        test_keys = [es256_holder_private_key_edn, es384_issuer_private_key_edn]

        for key_edn in test_keys:
            cbor_data = edn_utils.diag_to_cbor(key_edn)
            key = cbor_utils.decode(cbor_data)

            re_encoded = cbor_utils.encode(key)
            re_decoded = cbor_utils.decode(re_encoded)

            assert key == re_decoded, "CBOR roundtrip should preserve key structure"

    def test_key_validation_required_fields(self, es256_holder_private_key_edn, es384_issuer_private_key_edn):
        """Test that all keys have required fields according to specification."""
        # ES256 holder key
        cbor_data = edn_utils.diag_to_cbor(es256_holder_private_key_edn)
        holder_key = cbor_utils.decode(cbor_data)

        required_private_fields = {1, 3, -1, -2, -3, -4}  # kty, alg, crv, x, y, d
        assert all(field in holder_key for field in required_private_fields)

        # ES384 issuer key (includes kid)
        cbor_data = edn_utils.diag_to_cbor(es384_issuer_private_key_edn)
        issuer_key = cbor_utils.decode(cbor_data)

        required_issuer_fields = {1, 2, 3, -1, -2, -3, -4}  # kty, kid, alg, crv, x, y, d
        assert all(field in issuer_key for field in required_issuer_fields)

    def test_extract_public_keys_from_private(self, es256_holder_private_key_edn, es384_issuer_private_key_edn):
        """Test extracting public keys from private keys per specification."""
        # Extract ES256 holder public key
        cbor_data = edn_utils.diag_to_cbor(es256_holder_private_key_edn)
        private_key = cbor_utils.decode(cbor_data)
        public_key = {k: v for k, v in private_key.items() if k != -4}

        assert -4 not in public_key
        assert len(public_key) == 5  # kty, alg, crv, x, y

        # Extract ES384 issuer public key
        cbor_data = edn_utils.diag_to_cbor(es384_issuer_private_key_edn)
        private_key = cbor_utils.decode(cbor_data)
        public_key = {k: v for k, v in private_key.items() if k != -4}

        assert -4 not in public_key
        assert len(public_key) == 6  # kty, kid, alg, crv, x, y

    def test_algorithm_curve_consistency(self, es256_holder_private_key_edn, es384_issuer_private_key_edn):
        """Test that algorithm and curve parameters are consistent per specification."""
        # ES256 with P-256
        cbor_data = edn_utils.diag_to_cbor(es256_holder_private_key_edn)
        key = cbor_utils.decode(cbor_data)
        assert key[3] == -7   # ES256
        assert key[-1] == 1   # P-256
        assert len(key[-2]) == 32  # P-256 coordinates are 32 bytes

        # ES384 with P-384
        cbor_data = edn_utils.diag_to_cbor(es384_issuer_private_key_edn)
        key = cbor_utils.decode(cbor_data)
        assert key[3] == -35  # ES384
        assert key[-1] == 2   # P-384
        assert len(key[-2]) == 48  # P-384 coordinates are 48 bytes

    def test_private_key_ranges(self, es256_holder_private_key_edn, es384_issuer_private_key_edn):
        """Test that private key values are in valid ranges."""
        # ES256 (P-256)
        cbor_data = edn_utils.diag_to_cbor(es256_holder_private_key_edn)
        key = cbor_utils.decode(cbor_data)
        d_int = int.from_bytes(key[-4], 'big')
        assert 0 < d_int < 2**256

        # ES384 (P-384)
        cbor_data = edn_utils.diag_to_cbor(es384_issuer_private_key_edn)
        key = cbor_utils.decode(cbor_data)
        d_int = int.from_bytes(key[-4], 'big')
        assert 0 < d_int < 2**384

    def test_coordinate_non_zero(self, es256_holder_private_key_edn, es384_issuer_private_key_edn):
        """Test that public key coordinates are not zero."""
        # ES256
        cbor_data = edn_utils.diag_to_cbor(es256_holder_private_key_edn)
        key = cbor_utils.decode(cbor_data)
        assert key[-2] != b'\x00' * 32  # X coordinate not zero
        assert key[-3] != b'\x00' * 32  # Y coordinate not zero

        # ES384
        cbor_data = edn_utils.diag_to_cbor(es384_issuer_private_key_edn)
        key = cbor_utils.decode(cbor_data)
        assert key[-2] != b'\x00' * 48  # X coordinate not zero
        assert key[-3] != b'\x00' * 48  # Y coordinate not zero

    def test_specification_algorithm_corrections(self, es256_holder_private_key_edn, es384_issuer_private_key_edn):
        """Test corrections of specification algorithm errors."""
        # The specification shows incorrect algorithm values that we've corrected

        # ES256 holder key: spec shows -9 but should be -7 for ES256
        cbor_data = edn_utils.diag_to_cbor(es256_holder_private_key_edn)
        holder_key = cbor_utils.decode(cbor_data)
        assert holder_key[3] == -7, "ES256 algorithm should be -7, not -9 as shown in spec"

        # ES384 issuer key: spec shows -51 but should be -35 for ES384
        cbor_data = edn_utils.diag_to_cbor(es384_issuer_private_key_edn)
        issuer_key = cbor_utils.decode(cbor_data)
        assert issuer_key[3] == -35, "ES384 algorithm should be -35, not -51 as shown in spec"

    def test_cbor_pretty_print_structure(self, es256_holder_public_key_edn):
        """Test that CBOR structure matches specification pretty printing format."""
        cbor_data = edn_utils.diag_to_cbor(es256_holder_public_key_edn)
        key = cbor_utils.decode(cbor_data)

        # Re-encode and verify structure matches spec's CBOR pretty printing
        re_encoded = cbor_utils.encode(key)
        re_decoded = cbor_utils.decode(re_encoded)

        # Should match expected structure from specification lines 2478-2490
        assert len(re_decoded) == 4  # map(4)
        assert re_decoded[1] == 2    # kty: EC2
        assert re_decoded[-1] == 1   # crv: P-256
        assert len(re_decoded[-2]) == 32  # X coordinate: 32 bytes
        assert len(re_decoded[-3]) == 32  # Y coordinate: 32 bytes

    def test_issuer_key_id_specification_compliance(self, es384_issuer_private_key_edn):
        """Test that issuer key ID exactly matches specification."""
        cbor_data = edn_utils.diag_to_cbor(es384_issuer_private_key_edn)
        key = cbor_utils.decode(cbor_data)

        # Must match specification line 2543
        expected_kid = "https://issuer.example/cwk3.cbor"
        assert key[2] == expected_kid, "Key ID must exactly match specification"
        assert isinstance(key[2], str), "Key ID must be string type"
        assert key[2].startswith("https://"), "Key ID must be HTTPS URL"

    def test_interoperability_export_formats(self, es256_holder_private_key_edn, es384_issuer_private_key_edn):
        """Test exporting keys in formats suitable for interoperability testing."""
        keys = [es256_holder_private_key_edn, es384_issuer_private_key_edn]

        for key_edn in keys:
            cbor_data = edn_utils.diag_to_cbor(key_edn)
            key = cbor_utils.decode(cbor_data)
            public_key = {k: v for k, v in key.items() if k != -4}

            # Test hex export
            hex_export = cbor_utils.encode(public_key).hex()
            assert isinstance(hex_export, str)
            assert len(hex_export) > 0
            assert all(c in '0123456789abcdef' for c in hex_export.lower())

            # Test EDN export roundtrip
            edn_export = edn_utils.cbor_to_diag(cbor_utils.encode(public_key))
            assert "1:2" in edn_export or "1: 2" in edn_export  # kty: EC2

    def test_edn_format_specification_compliance(self, es256_holder_private_key_edn, es384_issuer_private_key_edn):
        """Test that EDN format parsing works correctly for specification examples."""
        # Test holder key EDN
        holder_cbor = edn_utils.diag_to_cbor(es256_holder_private_key_edn)
        holder_decoded = cbor_utils.decode(holder_cbor)

        # Convert back to EDN and verify roundtrip
        holder_roundtrip_edn = edn_utils.cbor_to_diag(holder_cbor)
        holder_roundtrip_cbor = edn_utils.diag_to_cbor(holder_roundtrip_edn)
        holder_roundtrip_decoded = cbor_utils.decode(holder_roundtrip_cbor)

        assert holder_decoded == holder_roundtrip_decoded, "Holder EDN roundtrip should preserve key"

        # Test issuer key EDN
        issuer_cbor = edn_utils.diag_to_cbor(es384_issuer_private_key_edn)
        issuer_decoded = cbor_utils.decode(issuer_cbor)

        # Convert back to EDN and verify roundtrip
        issuer_roundtrip_edn = edn_utils.cbor_to_diag(issuer_cbor)
        issuer_roundtrip_cbor = edn_utils.diag_to_cbor(issuer_roundtrip_edn)
        issuer_roundtrip_decoded = cbor_utils.decode(issuer_roundtrip_cbor)

        assert issuer_decoded == issuer_roundtrip_decoded, "Issuer EDN roundtrip should preserve key"