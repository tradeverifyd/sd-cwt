from sd_cwt import cbor_utils, edn_utils
from sd_cwt.cose_keys import cose_key_thumbprint


class TestIETF124:
    """Test IETF 124 compliance."""

    def test_holder_key_thumbprint(self):
        """Test key import and thumbprint generation for the holder key."""
        holder_key_edn = """
{
  /kty/  1 : 2, /EC/
  /alg/  3 : -7, /ES256/
  /crv/ -1 : 1, /P-256/
  /x/   -2 : h'8554eb275dcd6fbd1c7ac641aa2c90d9
              2022fd0d3024b5af18c7cc61ad527a2d',
  /y/   -3 : h'4dc7ae2c677e96d0cc82597655ce92d5
              503f54293d87875d1e79ce4770194343',
  /d/   -4 : h'5759a86e59bb3b002dde467da4b52f3d
              06e6c2cd439456cf0485b9b864294ce5'
}
        """


        cbor_data = edn_utils.diag_to_cbor(holder_key_edn)
        holder_key_dict = cbor_utils.decode(cbor_data)
        assert holder_key_dict is not None
        assert holder_key_dict[1] == 2
        assert holder_key_dict[3] == -7
        assert holder_key_dict[-1] == 1
        expected_x = bytes.fromhex('8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d')
        expected_y = bytes.fromhex('4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343')
        expected_d = bytes.fromhex('5759a86e59bb3b002dde467da4b52f3d06e6c2cd439456cf0485b9b864294ce5')
        assert holder_key_dict[-2] == expected_x
        assert holder_key_dict[-3] == expected_y
        assert holder_key_dict[-4] == expected_d

        thumbprint = cose_key_thumbprint(cbor_data)
        assert thumbprint is not None
        assert thumbprint == bytes.fromhex('8343d73cdfcb81f2c7cd11a5f317be8eb34e4807ec8c9ceb282495cffdf037e0')

    def test_issuer_key_thumbprint(self):
        """Test key import and thumbprint generation for the issuer key."""
        issuer_key_edn = """
{
    /kty/  1 : 2, /EC/
    /kid/  2 : "https://issuer.example/cwk3.cbor",
    /alg/  3 : -51, /ESP384/
    /crv/ -1 : 2, /P-384/
    /x/   -2 : h'c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307
                b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf',
    /y/   -3 : h'8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e
                84a055a31fb7f9214b27509522c159e764f8711e11609554',
    /d/   -4 : h'71c54d2221937ea612db1221f0d3ddf771c9381c4e3be41d
                5aa0a89d685f09cfef74c4bbf104783fd57e87ab227d074c'
}
        """

        cbor_data = edn_utils.diag_to_cbor(issuer_key_edn)
        issuer_key_dict = cbor_utils.decode(cbor_data)
        assert issuer_key_dict is not None
        assert issuer_key_dict[1] == 2
        assert issuer_key_dict[3] == -51
        assert issuer_key_dict[-1] == 2
        expected_x = bytes.fromhex('c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf')
        expected_y = bytes.fromhex('8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e84a055a31fb7f9214b27509522c159e764f8711e11609554')
        expected_d = bytes.fromhex('71c54d2221937ea612db1221f0d3ddf771c9381c4e3be41d5aa0a89d685f09cfef74c4bbf104783fd57e87ab227d074c')
        assert issuer_key_dict[-2] == expected_x

        thumbprint = cose_key_thumbprint(cbor_data)
        assert thumbprint is not None
        assert thumbprint == bytes.fromhex('554550a611c9807b3462cfec4a690a1119bc43b571da1219782133f5fd6dbcb0')