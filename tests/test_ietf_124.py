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
        expected_x = bytes.fromhex(
            "8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d"
        )
        expected_y = bytes.fromhex(
            "4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343"
        )
        expected_d = bytes.fromhex(
            "5759a86e59bb3b002dde467da4b52f3d06e6c2cd439456cf0485b9b864294ce5"
        )
        assert holder_key_dict[-2] == expected_x
        assert holder_key_dict[-3] == expected_y
        assert holder_key_dict[-4] == expected_d

        thumbprint = cose_key_thumbprint(cbor_data)
        assert thumbprint is not None
        assert thumbprint == bytes.fromhex(
            "8343d73cdfcb81f2c7cd11a5f317be8eb34e4807ec8c9ceb282495cffdf037e0"
        )

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
        expected_x = bytes.fromhex(
            "c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf"
        )
        expected_y = bytes.fromhex(
            "8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e84a055a31fb7f9214b27509522c159e764f8711e11609554"
        )
        expected_d = bytes.fromhex(
            "71c54d2221937ea612db1221f0d3ddf771c9381c4e3be41d5aa0a89d685f09cfef74c4bbf104783fd57e87ab227d074c"
        )
        assert issuer_key_dict[-2] == expected_x
        assert issuer_key_dict[-3] == expected_y
        assert issuer_key_dict[-4] == expected_d

        thumbprint = cose_key_thumbprint(cbor_data)
        assert thumbprint is not None
        assert thumbprint == bytes.fromhex(
            "554550a611c9807b3462cfec4a690a1119bc43b571da1219782133f5fd6dbcb0"
        )

    def test_minimal_spanning_example(self):
        """Test the minimal spanning example from the specification.

        This test verifies PARTIAL DISCLOSURE where the holder selectively reveals
        only some claims while keeping others redacted.

        DISCLOSED (3 disclosures present):
        1. inspector_license_number = "ABCD-123456" (top-level claim 501)
        2. inspection_dates[0] = 1549560720 (7-Feb-2019, array element)
        3. region = "ca" (nested in inspection_location)

        OMITTED (2 disclosures not included):
        1. inspection_dates[1] = 4-Feb-2021 (remains redacted with tag 60)
        2. postal_code in inspection_location (remains redacted)

        ALWAYS VISIBLE (never redacted):
        - Standard claims: iss, sub, exp, nbf, iat, cnf
        - most_recent_inspection_passed = true
        - inspection_dates[2] = 1674004740 (2023-01-17)
        - inspection_location.country = "us"
        """
        holder_key_edn = """
{
  /kty/  1 : 2,
  /alg/  3 : -7,
  /crv/ -1 : 1,
  /x/   -2 : h'8554eb275dcd6fbd1c7ac641aa2c90d9
              2022fd0d3024b5af18c7cc61ad527a2d',
  /y/   -3 : h'4dc7ae2c677e96d0cc82597655ce92d5
              503f54293d87875d1e79ce4770194343',
  /d/   -4 : h'5759a86e59bb3b002dde467da4b52f3d
              06e6c2cd439456cf0485b9b864294ce5'
}
        """

        issuer_key_edn = """
{
    /kty/  1 : 2,
    /kid/  2 : "https://issuer.example/cwk3.cbor",
    /alg/  3 : -51,
    /crv/ -1 : 2,
    /x/   -2 : h'c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307
                b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf',
    /y/   -3 : h'8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e
                84a055a31fb7f9214b27509522c159e764f8711e11609554',
    /d/   -4 : h'71c54d2221937ea612db1221f0d3ddf771c9381c4e3be41d
                5aa0a89d685f09cfef74c4bbf104783fd57e87ab227d074c'
}
        """

        minimal_spanning_example_edn = """

   / cose-sign1 / 18( / sd_kbt / [
     / KBT protected / << {
       / alg /    1:  -7, / ES256 /
       / kcwt /  13:  18([  / issuer SD-CWT /
         / CWT protected / << {
           / alg /    1  : -35, / ES384 /
           / kid /    4  : 'https://issuer.example/cose-key3',
           / typ /    16 : "application/sd-cwt",
           / sd_alg / 18 : -16  / SHA256 /
         } >>,
         / CWT unprotected / {
           / sd_claims / 17 : [ / these are the disclosures /
               <<[
                   /salt/   h'bae611067bb823486797da1ebbb52f83',
                   /value/  "ABCD-123456",
                   /claim/  501   / inspector_license_number /
               ]>>,
               <<[
                   /salt/   h'8de86a012b3043ae6e4457b9e1aaab80',
                   /value/  1549560720   / inspected 7-Feb-2019 /
               ]>>,
               <<[
                   /salt/   h'ec615c3035d5a4ff2f5ae29ded683c8e',
                   /value/  "ca",
                   /claim/  "region"   / region=California /
               ]>>,
           ]
         }
         / CWT payload / << {
           / iss / 1   : "https://issuer.example",
           / sub / 2   : "https://device.example",
           / exp / 4   : 1725330600,  /2024-09-03T02:30:00+00:00Z/
           / nbf / 5   : 1725243900,  /2024-09-02T02:25:00+00:00Z/
           / iat / 6   : 1725244200,  /2024-09-02T02:30:00+00:00Z/
           / cnf / 8   : {
             / cose key / 1 : {
               / kty /  1: 2,  / EC2   /
               / crv / -1: 1,  / P-256 /
               / x /   -2: h'8554eb275dcd6fbd1c7ac641aa2c90d9
                             2022fd0d3024b5af18c7cc61ad527a2d',
               / y /   -3: h'4dc7ae2c677e96d0cc82597655ce92d5
                             503f54293d87875d1e79ce4770194343'
             }
           },
           /most_recent_inspection_passed/ 500: true,
           /inspection_dates/ 502 : [
               / redacted inspection date 7-Feb-2019 /
               60(h'1b7fc8ecf4b1290712497d226c04b503
                    b4aa126c603c83b75d2679c3c613f3fd'),
               / redacted inspection date 4-Feb-2021 /
               60(h'64afccd3ad52da405329ad935de1fb36
                    814ec48fdfd79e3a108ef858e291e146'),
               1674004740,   / 2023-01-17T17:19:00 /
           ],
           / inspection_location / 503 : {
               "country" : "us",            / United States /
               / redacted_claim_keys / simple(59) : [
                   / redacted region /
                   h'0d4b8c6123f287a1698ff2db15764564
                     a976fb742606e8fd00e2140656ba0df3'
                   / redacted postal_code /
                   h'c0b7747f960fc2e201c4d47c64fee141
                     b78e3ab768ce941863dc8914e8f5815f'
             ]
           },
           / redacted_claim_keys / simple(59) : [
               / redacted inspector_license_number /
               h'af375dc3fba1d082448642c00be7b2f7
                 bb05c9d8fb61cfc230ddfdfb4616a693'
           ]
         } >>,
         / CWT signature / h'ed7ff84b27e746199698a94cc19292e4
                             b72dc4c3eb551f0ef2b9da07980c648c
                             2bb033c337c6ed13e1bc7c5b7b7c9df9
                             49a70239f51eca1f6d8e058b8b70bcb3
                             b5746812a932ffb37a2e6e984957e3f6
                             b003eb3319fbe21e97f6a3a273307424'
       ]),
       / end of issuer SD-CWT /
       / typ /   16:  "application/kb+cwt",
     } >>,     / end of KBT protected header /
     / KBT unprotected / {},
     / KBT payload / << {
       / aud    /  3    : "https://verifier.example/app",
       / iat    /  6    : 1725244237, / 2024-09-02T02:30:37+00:00Z /
       / cnonce / 39    : h'8c0f5f523b95bea44a9a48c649240803'
     } >>,      / end of KBT payload /
     / KBT signature / h'dd49379434b25b03cd8756787ab49731
                         580a04505439ca78ee53300dd49a00b7
                         0e8715d015a2a6e8d88455f5850e3d93
                         eade1366c0040c2cee1cc568322a6b93'
   ])   / end of kbt /
        """

        holder_key_cbor = edn_utils.diag_to_cbor(holder_key_edn)
        holder_key_dict = cbor_utils.decode(holder_key_cbor)
        holder_x = holder_key_dict[-2]
        holder_y = holder_key_dict[-3]

        issuer_key_cbor = edn_utils.diag_to_cbor(issuer_key_edn)
        issuer_key_dict = cbor_utils.decode(issuer_key_cbor)
        issuer_x = issuer_key_dict[-2]
        issuer_y = issuer_key_dict[-3]

        kbt_cbor = edn_utils.diag_to_cbor(minimal_spanning_example_edn)
        kbt_decoded = cbor_utils.decode(kbt_cbor)

        assert cbor_utils.is_tag(kbt_decoded)
        assert cbor_utils.get_tag_number(kbt_decoded) == 18

        kbt_array = cbor_utils.get_tag_value(kbt_decoded)
        assert isinstance(kbt_array, list)
        assert len(kbt_array) == 4

        kbt_protected_bytes = kbt_array[0]
        kbt_protected = cbor_utils.decode(kbt_protected_bytes)

        assert 13 in kbt_protected
        issuer_sd_cwt_cbor_or_data = kbt_protected[13]

        if isinstance(issuer_sd_cwt_cbor_or_data, bytes):
            issuer_sd_cwt_cbor = issuer_sd_cwt_cbor_or_data
        else:
            issuer_sd_cwt_cbor = cbor_utils.encode(issuer_sd_cwt_cbor_or_data)

        from sd_cwt.cose_sign1 import ES256Verifier, ES384Verifier, cose_sign1_verify

        issuer_verifier = ES384Verifier(issuer_x, issuer_y)
        issuer_valid, issuer_payload_bytes = cose_sign1_verify(issuer_sd_cwt_cbor, issuer_verifier)
        assert issuer_valid, "Issuer SD-CWT signature verification failed"
        assert issuer_payload_bytes is not None

        issuer_payload = cbor_utils.decode(issuer_payload_bytes)
        assert issuer_payload is not None
        assert issuer_payload[1] == "https://issuer.example"
        assert issuer_payload[2] == "https://device.example"

        assert 8 in issuer_payload
        cnf_claim = issuer_payload[8]
        assert 1 in cnf_claim
        holder_key_in_cnf = cnf_claim[1]
        assert holder_key_in_cnf[-2] == holder_x
        assert holder_key_in_cnf[-3] == holder_y

        issuer_sd_cwt_decoded = cbor_utils.decode(issuer_sd_cwt_cbor)
        issuer_sd_cwt_array = cbor_utils.get_tag_value(issuer_sd_cwt_decoded)
        issuer_unprotected = issuer_sd_cwt_array[1]
        assert 17 in issuer_unprotected
        disclosures = issuer_unprotected[17]
        assert len(disclosures) == 3

        holder_verifier = ES256Verifier(holder_x, holder_y)
        holder_valid, holder_payload_bytes = cose_sign1_verify(kbt_cbor, holder_verifier)
        assert holder_valid, "Holder KBT signature verification failed"
        assert holder_payload_bytes is not None

        holder_payload = cbor_utils.decode(holder_payload_bytes)
        assert holder_payload is not None
        assert holder_payload[3] == "https://verifier.example/app"
        assert holder_payload[6] == 1725244237

        disclosure_0 = cbor_utils.decode(disclosures[0])
        assert disclosure_0[0] == bytes.fromhex("bae611067bb823486797da1ebbb52f83")
        assert disclosure_0[1] == "ABCD-123456"
        assert disclosure_0[2] == 501

        disclosure_1 = cbor_utils.decode(disclosures[1])
        assert disclosure_1[0] == bytes.fromhex("8de86a012b3043ae6e4457b9e1aaab80")
        assert disclosure_1[1] == 1549560720
        assert len(disclosure_1) == 2

        disclosure_2 = cbor_utils.decode(disclosures[2])
        assert disclosure_2[0] == bytes.fromhex("ec615c3035d5a4ff2f5ae29ded683c8e")
        assert disclosure_2[1] == "ca"
        assert disclosure_2[2] == "region"

        simple_59 = cbor_utils.create_simple_value(59)
        assert simple_59 in issuer_payload
        redacted_top_level = issuer_payload[simple_59]
        assert len(redacted_top_level) == 1
        expected_inspector_hash = bytes.fromhex(
            "af375dc3fba1d082448642c00be7b2f7bb05c9d8fb61cfc230ddfdfb4616a693"
        )
        assert redacted_top_level[0] == expected_inspector_hash

        assert 502 in issuer_payload
        inspection_dates = issuer_payload[502]
        assert len(inspection_dates) == 3

        assert cbor_utils.is_tag(inspection_dates[0])
        assert cbor_utils.get_tag_number(inspection_dates[0]) == 60
        redacted_date_1_hash = cbor_utils.get_tag_value(inspection_dates[0])
        assert redacted_date_1_hash == bytes.fromhex(
            "1b7fc8ecf4b1290712497d226c04b503b4aa126c603c83b75d2679c3c613f3fd"
        )

        assert cbor_utils.is_tag(inspection_dates[1])
        assert cbor_utils.get_tag_number(inspection_dates[1]) == 60
        redacted_date_2_hash = cbor_utils.get_tag_value(inspection_dates[1])
        assert redacted_date_2_hash == bytes.fromhex(
            "64afccd3ad52da405329ad935de1fb36814ec48fdfd79e3a108ef858e291e146"
        )

        assert inspection_dates[2] == 1674004740

        assert 503 in issuer_payload
        inspection_location = issuer_payload[503]
        assert inspection_location["country"] == "us"
        assert simple_59 in inspection_location
        redacted_location_keys = inspection_location[simple_59]
        assert len(redacted_location_keys) == 2
        expected_region_hash = bytes.fromhex(
            "0d4b8c6123f287a1698ff2db15764564a976fb742606e8fd00e2140656ba0df3"
        )
        expected_postal_hash = bytes.fromhex(
            "c0b7747f960fc2e201c4d47c64fee141b78e3ab768ce941863dc8914e8f5815f"
        )
        assert redacted_location_keys[0] == expected_region_hash
        assert redacted_location_keys[1] == expected_postal_hash

        print("\n✓ PARTIAL DISCLOSURE VERIFIED:")
        print("  • Issuer ES384 signature: VALID")
        print("  • Holder ES256 signature: VALID")
        print(f"  • Disclosures present: {len(disclosures)}")
        print(f"    1. inspector_license_number = {disclosure_0[1]}")
        print(f"    2. inspection_dates[0] = {disclosure_1[1]} (7-Feb-2019)")
        print(f"    3. region = {disclosure_2[1]}")
        print("  • Omitted disclosures still redacted:")
        print(f"    1. inspection_dates[1] with hash {redacted_date_2_hash.hex()[:16]}...")
        print(f"    2. postal_code with hash {expected_postal_hash.hex()[:16]}...")
        print("  • Always visible claims: iss, sub, exp, nbf, iat, cnf, country=us")
