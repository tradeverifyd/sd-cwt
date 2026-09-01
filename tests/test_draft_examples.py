"""Conformance tests against the canonical examples in draft-ietf-spice-sd-cwt-08.

Every other test in this suite signs and verifies with this library on both
sides, so it passes whenever the library is self-consistent -- including when it
is self-consistently wrong. These tests are the opposite: the bytes are fixed by
the draft, and the library has to meet them.

Fixtures and key provenance: tests/fixtures/draft-08/README.md
"""

from pathlib import Path

import pytest

from sd_cwt import cbor_utils
from sd_cwt.holder_binding import kcwt_to_bytes
from sd_cwt.redaction import hash_disclosure
from sd_cwt.verifiers import CredentialVerifier, get_presentation_verifier

FIXTURES = Path(__file__).parent / "fixtures" / "draft-08"

# Appendix C.2: Issuer key, P-384 / ES384.
ISSUER_PUBLIC_KEY = {
    1: 2,  # kty: EC2
    -1: 2,  # crv: P-384
    -2: bytes.fromhex(
        "c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307"
        "b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf"
    ),
    -3: bytes.fromhex(
        "8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e"
        "84a055a31fb7f9214b27509522c159e764f8711e11609554"
    ),
}

AUDIENCE = "https://verifier.example/app"


@pytest.fixture
def issued() -> bytes:
    return (FIXTURES / "issuer_cwt.cbor").read_bytes()


@pytest.fixture
def kbt() -> bytes:
    return (FIXTURES / "kbt.cbor").read_bytes()


@pytest.fixture
def issuer_resolver():
    # kid is present in the draft's example, but the resolver must tolerate its
    # absence because kid is optional in an SD-CWT protected header.
    return lambda kid: ISSUER_PUBLIC_KEY


class TestIssuedSdCwt:
    """The issued SD-CWT, examples/issuer_cwt.cbor."""

    def test_protected_headers_match_the_draft(self, issued: bytes) -> None:
        arr = cbor_utils.get_tag_value(cbor_utils.decode(issued))
        protected = cbor_utils.decode(arr[0])

        assert protected[1] == -35, "alg must be ES384"
        assert protected[16] == 293, "typ must be the CoAP content-format 293"
        assert protected[170] == -16, "sd_alg must be SHA-256"
        assert len(arr[1][17]) == 5, "the Issuer sends five disclosures in sd_claims"

    def test_verifies_under_the_appendix_c_issuer_key(self, issued, issuer_resolver) -> None:
        # Regression guard: the verifier must be chosen from the alg in the
        # protected header. Assuming ES256 rejects this ES384 signature.
        is_valid, payload = CredentialVerifier(issuer_resolver).verify(issued)

        assert is_valid, "the draft's issued SD-CWT must verify"
        assert payload is not None
        assert payload[1] == "https://issuer.example"

    def test_payload_is_not_double_encoded(self, issued, issuer_resolver) -> None:
        # The payload bstr holds the CWT Claims Set directly. A nested bstr
        # decodes to bytes here and no other implementation can read it.
        arr = cbor_utils.get_tag_value(cbor_utils.decode(issued))
        payload = cbor_utils.decode(arr[2])

        assert isinstance(payload, dict), "payload must decode straight to a claims map"


class TestRedactedClaimHash:
    """The digest construction, which is where implementations diverge."""

    # The CDDL says `bstr-encoded-salted = bstr .cbor salted-entry`, so the
    # digest covers the byte string including its header. This is the exact
    # disclosure the draft walks through in Section 3.
    SALTED_ENTRY = bytes.fromhex(
        "8350bae611067bb823486797da1ebbb52f836b414243442d3132333435361901f5"
    )
    REDACTED_CLAIM_HASH = "af375dc3fba1d082448642c00be7b2f7bb05c9d8fb61cfc230ddfdfb4616a693"

    def test_hashes_the_bstr_matching_the_issued_payload(self) -> None:
        assert hash_disclosure(self.SALTED_ENTRY).hex() == self.REDACTED_CLAIM_HASH

    def test_digest_appears_in_the_issued_payload(self, issued: bytes) -> None:
        arr = cbor_utils.get_tag_value(cbor_utils.decode(issued))
        payload = cbor_utils.decode(arr[2])
        redacted_claim_keys = payload[cbor_utils.create_simple_value(59)]

        assert bytes.fromhex(self.REDACTED_CLAIM_HASH) in redacted_claim_keys

    def test_does_not_hash_the_bare_array_encoding(self) -> None:
        import hashlib

        # d9df03da… is what hashing SALTED_ENTRY directly produces. Two
        # independent implementations shipped that digest; nothing verifies it.
        wrong = hashlib.sha256(self.SALTED_ENTRY).hexdigest()
        assert wrong != self.REDACTED_CLAIM_HASH


class TestPresentation:
    """The SD-KBT presentation, examples/kbt.cbor."""

    def test_typ_is_the_integer_content_format(self, kbt: bytes) -> None:
        arr = cbor_utils.get_tag_value(cbor_utils.decode(kbt))
        protected = cbor_utils.decode(arr[0])

        assert protected[16] == 294
        assert 4 not in protected, "an SD-KBT has no kid; cnf pins the Holder key"

    def test_kcwt_is_the_embedded_tag_18_structure(self, kbt: bytes) -> None:
        arr = cbor_utils.get_tag_value(cbor_utils.decode(kbt))
        protected = cbor_utils.decode(arr[0])
        kcwt = protected[13]

        assert cbor_utils.is_tag(kcwt), "kcwt must be the embedded #6.18, not a bstr"
        assert kcwt.tag == 18

    def test_verifies_end_to_end(self, kbt, issuer_resolver) -> None:
        arr = cbor_utils.get_tag_value(cbor_utils.decode(kbt))
        embedded = kcwt_to_bytes(cbor_utils.decode(arr[0])[13])

        credential_verifier = CredentialVerifier(issuer_resolver)
        is_valid, _ = credential_verifier.verify(embedded)
        assert is_valid, "the embedded SD-CWT must verify under the Issuer key"

        # The Holder key comes from the cnf claim, not from a kid lookup.
        presentation_verifier = get_presentation_verifier(embedded, credential_verifier)
        assert presentation_verifier is not None

        is_valid, kbt_payload = presentation_verifier.verify(kbt, audience=AUDIENCE)
        assert is_valid, "the SD-KBT must verify under the cnf key"
        assert kbt_payload is not None
        assert kbt_payload[3] == AUDIENCE
        assert kbt_payload[6] == 1725244237
        assert kbt_payload[39] == bytes.fromhex("8c0f5f523b95bea44a9a48c649240803")

    def test_rejects_a_different_audience(self, kbt, issuer_resolver) -> None:
        arr = cbor_utils.get_tag_value(cbor_utils.decode(kbt))
        embedded = kcwt_to_bytes(cbor_utils.decode(arr[0])[13])

        credential_verifier = CredentialVerifier(issuer_resolver)
        presentation_verifier = get_presentation_verifier(embedded, credential_verifier)
        assert presentation_verifier is not None

        is_valid, _ = presentation_verifier.verify(kbt, audience="https://attacker.example")
        assert not is_valid

    def test_every_presented_disclosure_matches_a_redacted_hash(self, kbt: bytes) -> None:
        arr = cbor_utils.get_tag_value(cbor_utils.decode(kbt))
        embedded = kcwt_to_bytes(cbor_utils.decode(arr[0])[13])
        embedded_arr = cbor_utils.get_tag_value(cbor_utils.decode(embedded))

        disclosures = embedded_arr[1][17]
        assert len(disclosures) == 3, "the Holder selected three of the five disclosures"

        payload = cbor_utils.decode(embedded_arr[2])

        # Gather every Redacted Claim Hash: the simple(59) arrays for redacted
        # map keys, and the tag 60 contents for redacted array elements.
        redacted_hashes: set[bytes] = set()

        def collect(node: object) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == cbor_utils.create_simple_value(59):
                        redacted_hashes.update(value)
                    else:
                        collect(value)
            elif isinstance(node, list):
                for item in node:
                    if cbor_utils.is_tag(item, 60):
                        redacted_hashes.add(item.value)
                    else:
                        collect(item)

        collect(payload)

        for disclosure in disclosures:
            digest = hash_disclosure(disclosure)
            entry = cbor_utils.decode(disclosure)
            assert digest in redacted_hashes, f"no Redacted Claim Hash matches {entry}"


def _cose_private_key(pem_path: Path, crv: int) -> dict:
    """Load an Appendix C PEM key as a COSE_Key map."""
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(pem_path.read_bytes(), password=None)
    private = key.private_numbers()
    public = key.public_key().public_numbers()
    size = (key.curve.key_size + 7) // 8
    return {
        1: 2,  # kty: EC2
        3: {1: -7, 2: -35, 3: -36}[crv],  # alg implied by the curve
        -1: crv,
        -2: public.x.to_bytes(size, "big"),
        -3: public.y.to_bytes(size, "big"),
        -4: private.private_value.to_bytes(size, "big"),
    }


class TestRolesWithAppendixCKeys:
    """Issue, present and verify using the draft's own Appendix C key pair.

    The Issuer key is P-384 / ES384 and the Holder key is P-256 / ES256, so this
    also pins that neither role assumes ES256.
    """

    @pytest.fixture
    def keys(self) -> tuple[dict, dict]:
        return (
            _cose_private_key(FIXTURES / "issuer_privkey.pem", 2),
            _cose_private_key(FIXTURES / "holder_privkey.pem", 1),
        )

    def test_issues_with_the_es384_issuer_key(self, keys) -> None:
        from sd_cwt.simple_api import SDCWTIssuer

        issuer_key, holder_key = keys
        holder_pub = {k: v for k, v in holder_key.items() if k != -4}

        sd_cwt, _edn, disclosures = SDCWTIssuer(issuer_key).issue_credential(
            base_claims={"most_recent_inspection_passed": True},
            optional_claims={"inspector_license_number": "ABCD-123456"},
            holder_public_key=cbor_utils.encode(holder_pub),
            subject="https://holder.example",
        )

        arr = cbor_utils.get_tag_value(cbor_utils.decode(sd_cwt))
        protected = cbor_utils.decode(arr[0])
        assert protected[1] == -35, "alg must follow the Issuer key, not default to ES256"
        assert protected[16] == 293
        assert len(disclosures) == 1

    def test_full_round_trip_and_raw_byte_cnonce(self, keys) -> None:
        from sd_cwt.simple_api import SDCWTIssuer, SDCWTPresenter

        issuer_key, holder_key = keys
        issuer_pub = {k: v for k, v in issuer_key.items() if k != -4}
        holder_pub = {k: v for k, v in holder_key.items() if k != -4}

        sd_cwt, _edn, disclosures = SDCWTIssuer(issuer_key).issue_credential(
            base_claims={"most_recent_inspection_passed": True},
            optional_claims={"inspector_license_number": "ABCD-123456"},
            holder_public_key=cbor_utils.encode(holder_pub),
            subject="https://holder.example",
        )

        # A Verifier's cnonce is arbitrary bytes and need not be valid UTF-8.
        cnonce = bytes.fromhex("8c0f5f523b95bea44a9a48c649240803")
        kbt = SDCWTPresenter(holder_key).create_presentation(
            sd_cwt=sd_cwt,
            disclosures=disclosures,
            selected_disclosures=disclosures,
            audience=AUDIENCE,
            nonce=cnonce,
        )

        protected = cbor_utils.decode(cbor_utils.get_tag_value(cbor_utils.decode(kbt))[0])
        embedded = kcwt_to_bytes(protected[13])

        credential_verifier = CredentialVerifier(lambda kid: issuer_pub)
        is_valid, _ = credential_verifier.verify(embedded)
        assert is_valid, "ES384 Issuer signature must verify"

        presentation_verifier = get_presentation_verifier(embedded, credential_verifier)
        assert presentation_verifier is not None
        is_valid, payload = presentation_verifier.verify(kbt, audience=AUDIENCE)
        assert is_valid, "ES256 Holder signature must verify"
        assert payload[39] == cnonce, "cnonce MUST be echoed as the exact bytes given"

    def test_presents_the_drafts_own_credential(self, issued, keys, issuer_resolver) -> None:
        """Act as Holder over examples/issuer_cwt.cbor and verify the result."""
        from sd_cwt.simple_api import SDCWTPresenter

        _issuer_key, holder_key = keys
        arr = cbor_utils.get_tag_value(cbor_utils.decode(issued))
        all_disclosures = arr[1][17]
        assert len(all_disclosures) == 5

        def label(disclosure):
            entry = cbor_utils.decode(disclosure)
            return entry[2] if len(entry) == 3 else entry[1]

        wanted = {501, 1549560720, "region"}
        selected = [d for d in all_disclosures if label(d) in wanted]
        assert len(selected) == 3

        kbt = SDCWTPresenter(holder_key).create_presentation(
            sd_cwt=issued,
            disclosures=all_disclosures,
            selected_disclosures=selected,
            audience=AUDIENCE,
        )

        protected = cbor_utils.decode(cbor_utils.get_tag_value(cbor_utils.decode(kbt))[0])
        embedded = kcwt_to_bytes(protected[13])

        credential_verifier = CredentialVerifier(issuer_resolver)
        is_valid, _ = credential_verifier.verify(embedded)
        assert is_valid

        presentation_verifier = get_presentation_verifier(embedded, credential_verifier)
        assert presentation_verifier is not None
        is_valid, _ = presentation_verifier.verify(kbt, audience=AUDIENCE)
        assert is_valid

        # Every carried disclosure must still match a Redacted Claim Hash.
        embedded_arr = cbor_utils.get_tag_value(cbor_utils.decode(embedded))
        payload = cbor_utils.decode(embedded_arr[2])
        redacted: set[bytes] = set()

        def collect(node: object) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == cbor_utils.create_simple_value(59):
                        redacted.update(value)
                    else:
                        collect(value)
            elif isinstance(node, list):
                for item in node:
                    if cbor_utils.is_tag(item, 60):
                        redacted.add(item.value)
                    else:
                        collect(item)

        collect(payload)
        for disclosure in embedded_arr[1][17]:
            assert hash_disclosure(disclosure) in redacted
