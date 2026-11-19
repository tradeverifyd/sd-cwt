"""AEAD encrypted disclosures, draft-ietf-spice-sd-cwt-09 Section "Encrypted Disclosures"."""

import pytest

from fixture_clock import issuance_time, verify_fixture
from sd_cwt import (
    AEAD_AES_128_GCM,
    AEAD_AES_256_GCM,
    AEAD_CHACHA20_POLY1305,
    AeadDisclosureError,
    cbor_utils,
    decrypt_disclosure,
    decrypt_sd_cwt_disclosures,
    encrypt_disclosure,
    encrypt_sd_cwt_disclosures,
)
from sd_cwt.holder_binding import kcwt_to_bytes
from sd_cwt.simple_api import SDCWTPresenter, SDCWTVerifier
from test_draft_examples import AUDIENCE, FIXTURES, ISSUER_PUBLIC_KEY, _cose_private_key

# examples/aead-key.txt and examples/aead-claim-array.edn
DRAFT_KEY = bytes.fromhex("a061c27a3273721e210d031863ad81b6")
DRAFT_ENTRY = [
    bytes.fromhex("95d0040fe650e5baf51c907c"),
    bytes.fromhex("563a7d9f0f65d40b751fbc3fcc408e8fe27c375b60a4727b1f1e9572c07992eb5ec5a9"),
    bytes.fromhex("9f4d37da32187528416ed7ee95e0625f"),
]
# examples/first-disclosure.edn
FIRST_DISCLOSURE = cbor_utils.encode(
    [bytes.fromhex("bae611067bb823486797da1ebbb52f83"), "ABCD-123456", 501]
)

OTHER_KEY = bytes(16)


@pytest.fixture
def issued() -> bytes:
    return (FIXTURES / "issuer_cwt.cbor").read_bytes()


@pytest.fixture
def holder_key() -> dict:
    return _cose_private_key(FIXTURES / "holder_privkey.pem", 1)


@pytest.fixture
def disclosures(issued: bytes) -> dict:
    sd_claims = cbor_utils.get_tag_value(cbor_utils.decode(issued))[1][17]
    return {cbor_utils.decode(d)[-1]: d for d in sd_claims}


def _verifier() -> SDCWTVerifier:
    return SDCWTVerifier(lambda kid: ISSUER_PUBLIC_KEY)


def _embedded_unprotected(kbt: bytes) -> dict:
    protected = cbor_utils.decode(cbor_utils.get_tag_value(cbor_utils.decode(kbt))[0])
    return cbor_utils.get_tag_value(cbor_utils.decode(kcwt_to_bytes(protected[13])))[1]


class TestDraftVector:
    def test_decrypts_to_the_first_disclosure(self) -> None:
        assert decrypt_disclosure(DRAFT_ENTRY, DRAFT_KEY) == FIRST_DISCLOSURE

    def test_encrypts_byte_identically_with_the_drafts_nonce(self) -> None:
        assert encrypt_disclosure(FIRST_DISCLOSURE, DRAFT_KEY, nonce=DRAFT_ENTRY[0]) == DRAFT_ENTRY

    def test_plaintext_includes_the_bstr_header(self) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce, ciphertext, tag = DRAFT_ENTRY
        plaintext = AESGCM(DRAFT_KEY).decrypt(nonce, ciphertext + tag, b"")
        assert plaintext[:2] == bytes.fromhex("5821")
        assert plaintext[2:] == FIRST_DISCLOSURE

    def test_first_disclosure_is_in_the_drafts_credential(self, disclosures) -> None:
        assert disclosures[501] == FIRST_DISCLOSURE


class TestEncryptDecrypt:
    @pytest.mark.parametrize(
        ("alg", "key"),
        [
            (AEAD_AES_128_GCM, bytes(range(16))),
            (AEAD_AES_256_GCM, bytes(range(32))),
            (AEAD_CHACHA20_POLY1305, bytes(range(32))),
        ],
    )
    def test_round_trip(self, alg, key) -> None:
        entry = encrypt_disclosure(FIRST_DISCLOSURE, key, alg=alg)
        assert len(entry[0]) == 12 and len(entry[2]) == 16
        assert decrypt_disclosure(entry, key, alg=alg) == FIRST_DISCLOSURE

    def test_nonce_is_fresh(self) -> None:
        a = encrypt_disclosure(FIRST_DISCLOSURE, DRAFT_KEY)
        b = encrypt_disclosure(FIRST_DISCLOSURE, DRAFT_KEY)
        assert a[0] != b[0]

    @pytest.mark.parametrize("context", [7, "verifier-1", bytes(32)])
    def test_key_context_is_carried(self, context) -> None:
        entry = encrypt_disclosure(FIRST_DISCLOSURE, DRAFT_KEY, key_context=context)
        assert entry[3] == context
        assert decrypt_disclosure(entry, DRAFT_KEY) == FIRST_DISCLOSURE

    @pytest.mark.parametrize("context", [-1, True, 1.5, [1]])
    def test_rejects_an_invalid_key_context(self, context) -> None:
        with pytest.raises(AeadDisclosureError):
            encrypt_disclosure(FIRST_DISCLOSURE, DRAFT_KEY, key_context=context)
        with pytest.raises(AeadDisclosureError):
            decrypt_disclosure(DRAFT_ENTRY + [context], DRAFT_KEY)

    def test_rejects_the_wrong_key(self) -> None:
        with pytest.raises(AeadDisclosureError, match="authentication"):
            decrypt_disclosure(DRAFT_ENTRY, OTHER_KEY)

    def test_rejects_a_tampered_tag(self) -> None:
        tag = bytes([DRAFT_ENTRY[2][0] ^ 1]) + DRAFT_ENTRY[2][1:]
        with pytest.raises(AeadDisclosureError, match="authentication"):
            decrypt_disclosure([DRAFT_ENTRY[0], DRAFT_ENTRY[1], tag], DRAFT_KEY)

    @pytest.mark.parametrize(
        "entry",
        [
            DRAFT_ENTRY[:2],
            [DRAFT_ENTRY[0][:8], DRAFT_ENTRY[1], DRAFT_ENTRY[2]],
            [DRAFT_ENTRY[0], DRAFT_ENTRY[1], DRAFT_ENTRY[2][:12]],
            [DRAFT_ENTRY[0], "ciphertext", DRAFT_ENTRY[2]],
        ],
    )
    def test_rejects_a_malformed_entry(self, entry) -> None:
        with pytest.raises(AeadDisclosureError):
            decrypt_disclosure(entry, DRAFT_KEY)

    @pytest.mark.parametrize("alg", [0, 3, 20, 24, True])
    def test_rejects_unsupported_algorithms(self, alg) -> None:
        with pytest.raises(AeadDisclosureError, match="unsupported"):
            encrypt_disclosure(FIRST_DISCLOSURE, DRAFT_KEY, alg=alg)

    def test_rejects_a_plaintext_that_is_not_a_bstr(self) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = bytes(12)
        sealed = AESGCM(DRAFT_KEY).encrypt(nonce, FIRST_DISCLOSURE, b"")
        with pytest.raises(AeadDisclosureError, match="bstr"):
            decrypt_disclosure([nonce, sealed[:-16], sealed[-16:]], DRAFT_KEY)


class TestHeaders:
    def test_omits_empty_arrays(self, issued, disclosures) -> None:
        only_encrypted = encrypt_sd_cwt_disclosures(issued, [], [disclosures[501]], DRAFT_KEY)
        unprotected = cbor_utils.get_tag_value(cbor_utils.decode(only_encrypted))[1]
        assert 17 not in unprotected and len(unprotected[171]) == 1

        only_plaintext = encrypt_sd_cwt_disclosures(issued, [disclosures[501]], [], DRAFT_KEY)
        unprotected = cbor_utils.get_tag_value(cbor_utils.decode(only_plaintext))[1]
        assert 171 not in unprotected and unprotected[17] == [disclosures[501]]

    def test_rejects_an_empty_encrypted_claims_array(self, issued) -> None:
        arr = cbor_utils.get_tag_value(cbor_utils.decode(issued))
        arr[1] = {171: []}
        token = cbor_utils.encode(cbor_utils.create_tag(18, arr))
        with pytest.raises(AeadDisclosureError, match="non-empty"):
            decrypt_sd_cwt_disclosures(token, lambda ctx: DRAFT_KEY)

    def test_without_a_key_entries_are_left_for_forwarding(self, issued, disclosures) -> None:
        token = encrypt_sd_cwt_disclosures(issued, [], [disclosures[501]], DRAFT_KEY)
        out, remaining = decrypt_sd_cwt_disclosures(token, lambda ctx: None)
        assert len(remaining) == 1
        assert cbor_utils.get_tag_value(cbor_utils.decode(out))[1][171] == remaining

    def test_resolver_receives_the_key_context(self, issued, disclosures) -> None:
        token = encrypt_sd_cwt_disclosures(
            issued, [], [disclosures[501]], DRAFT_KEY, key_context="rp-1"
        )
        seen = []

        def resolver(ctx):
            seen.append(ctx)
            return [OTHER_KEY, DRAFT_KEY]

        out, remaining = decrypt_sd_cwt_disclosures(token, resolver)
        assert seen == ["rp-1"] and remaining == []
        assert cbor_utils.get_tag_value(cbor_utils.decode(out))[1][17] == [disclosures[501]]

    def test_uses_sd_aead_from_the_unprotected_header(self, holder_key, disclosures) -> None:
        from sd_cwt.simple_api import SDCWTIssuer

        issuer_key = _cose_private_key(FIXTURES / "issuer_privkey.pem", 2)
        holder_public = cbor_utils.encode({k: v for k, v in holder_key.items() if k != -4})
        token, _edn, all_disclosures = SDCWTIssuer(issuer_key).issue_credential(
            base_claims={"a": 1},
            optional_claims={"b": 2},
            holder_public_key=holder_public,
            sd_aead=AEAD_CHACHA20_POLY1305,
        )
        key = bytes(range(32))
        sealed = encrypt_sd_cwt_disclosures(token, [], all_disclosures, key)
        entry = cbor_utils.get_tag_value(cbor_utils.decode(sealed))[1][171][0]
        assert decrypt_disclosure(entry, key, alg=AEAD_CHACHA20_POLY1305) == all_disclosures[0]
        with pytest.raises(AeadDisclosureError):
            encrypt_sd_cwt_disclosures(token, [], all_disclosures, DRAFT_KEY)


class TestPresentation:
    def _present(self, issued, holder_key, disclosures, **kwargs) -> bytes:
        return SDCWTPresenter(holder_key).create_presentation(
            sd_cwt=issued,
            issued_at=issuance_time(issued),
            disclosures=list(disclosures.values()),
            selected_disclosures=[disclosures[1549560720], disclosures["region"]],
            audience=AUDIENCE,
            encrypted_disclosures=[disclosures[501]],
            aead_key=DRAFT_KEY,
            **kwargs,
        )

    def test_encrypted_disclosure_moves_to_header_171(self, issued, holder_key, disclosures):
        unprotected = _embedded_unprotected(self._present(issued, holder_key, disclosures))
        assert disclosures[501] not in unprotected[17]
        assert len(unprotected[17]) == 2 and len(unprotected[171]) == 1

    def test_verifier_with_the_key_sees_the_claim(self, issued, holder_key, disclosures):
        kbt = self._present(issued, holder_key, disclosures)
        valid, claims, _ = verify_fixture(kbt, AUDIENCE, aead_key_resolver=lambda ctx: DRAFT_KEY)
        assert valid and claims is not None
        assert claims[501] == "ABCD-123456"
        assert claims[501] == "ABCD-123456"
        assert claims[503]["region"] == "ca"

    def test_verifier_without_the_key_still_verifies(self, issued, holder_key, disclosures):
        kbt = self._present(issued, holder_key, disclosures)
        valid, claims, _ = verify_fixture(kbt, AUDIENCE)
        assert valid and claims is not None
        assert 501 not in claims
        assert claims[503]["region"] == "ca"

    def test_wrong_key_rejects_the_presentation(self, issued, holder_key, disclosures):
        kbt = self._present(issued, holder_key, disclosures)
        valid, _claims, _ = verify_fixture(kbt, AUDIENCE, aead_key_resolver=lambda ctx: OTHER_KEY)
        assert not valid

    def test_requires_a_key_to_encrypt(self, issued, holder_key, disclosures):
        with pytest.raises(ValueError, match="aead_key"):
            SDCWTPresenter(holder_key).create_presentation(
                sd_cwt=issued,
                issued_at=issuance_time(issued),
                disclosures=[],
                selected_disclosures=[],
                audience=AUDIENCE,
                encrypted_disclosures=[disclosures[501]],
            )

    def test_decrypted_disclosure_must_match_a_redacted_hash(self, holder_key):
        """A disclosure from another credential, smuggled in encrypted, is rejected."""
        issued = (FIXTURES / "decoy.cbor").read_bytes()
        foreign = cbor_utils.encode([bytes(16), "forged", 501])
        kbt = SDCWTPresenter(holder_key).create_presentation(
            sd_cwt=issued,
            issued_at=issuance_time(issued),
            disclosures=[],
            selected_disclosures=[],
            audience=AUDIENCE,
            encrypted_disclosures=[foreign],
            aead_key=DRAFT_KEY,
        )
        valid, _claims, _ = verify_fixture(kbt, AUDIENCE, aead_key_resolver=lambda ctx: DRAFT_KEY)
        assert not valid
        valid, _claims, _ = verify_fixture(kbt, AUDIENCE)
        assert valid, "a Verifier that cannot decrypt cannot detect it, and forwards it"


@pytest.mark.parametrize("filename", ["aead_kbt.cbor", "aead_kbt.js.cbor"])
class TestCrossImplementationFixtures:
    """Presentations of the draft's credential with its first disclosure encrypted."""

    def test_verifies_and_decrypts(self, filename) -> None:
        path = FIXTURES / filename
        if not path.exists():
            pytest.skip(f"{filename} not checked in")
        kbt = path.read_bytes()
        entries = _embedded_unprotected(kbt)[171]
        assert entries == [DRAFT_ENTRY], "must match the draft's aead-claim-array.edn"

        valid, claims, _ = verify_fixture(kbt, AUDIENCE, aead_key_resolver=lambda ctx: DRAFT_KEY)
        assert valid and claims is not None
        assert claims[501] == "ABCD-123456"
        assert claims[501] == "ABCD-123456"


@pytest.mark.parametrize("plaintext_duplicate", [False, True])
def test_duplicate_decrypted_disclosures_reject(issued, holder_key, plaintext_duplicate):
    from sd_cwt.holder_binding import create_sd_kbt
    from sd_cwt.signers import PresentationSigner

    # Different nonces prove we compare recovered disclosures, not ciphertexts.
    token = encrypt_sd_cwt_disclosures(
        issued,
        [FIRST_DISCLOSURE] if plaintext_duplicate else [],
        [FIRST_DISCLOSURE] if plaintext_duplicate else [FIRST_DISCLOSURE, FIRST_DISCLOSURE],
        DRAFT_KEY,
    )
    with pytest.raises(AeadDisclosureError, match="duplicate disclosure"):
        decrypt_sd_cwt_disclosures(token, lambda ctx: DRAFT_KEY)

    kbt = create_sd_kbt(
        sd_cwt_with_disclosures=token,
        holder_signer=PresentationSigner(holder_key),
        audience=AUDIENCE,
        issued_at=issuance_time(issued),
    )
    valid, _, _ = verify_fixture(kbt, AUDIENCE, aead_key_resolver=lambda ctx: DRAFT_KEY)
    assert not valid
    # Without the key a duplicate cannot be detected; forwarding is still valid.
    valid, _, _ = verify_fixture(kbt, AUDIENCE)
    assert valid


class TestNestedCrossImplementation:
    """Generated by the draft repository's interop/run_profiles.py, JS Holder."""

    @pytest.mark.parametrize("with_key", [False, True])
    def test_nested_and_array_disclosures_keep_their_locations(self, with_key):
        token = (FIXTURES / "nested_aead.js.cbor").read_bytes()
        valid, claims, clean = verify_fixture(
            token, AUDIENCE, aead_key_resolver=(lambda ctx: DRAFT_KEY) if with_key else None
        )
        expected = {
            "iss": "https://issuer.example",
            "sub": "https://holder.example",
            500: True,
            "items": ["public"],
        }
        if with_key:
            expected["profile"] = {"public": True, "city": "private city"}
            expected["items"].append({"kind": "secret"})
        assert valid and clean
        assert claims == expected

    @pytest.mark.parametrize("recipient", ["both", "a", "b", "neither"])
    def test_context_routing_and_partial_decryption(self, recipient):
        token = (FIXTURES / "two_key_aead.js.cbor").read_bytes()
        mapping = {}
        if recipient in ("both", "a"):
            mapping[bytes(range(32))] = DRAFT_KEY
        if recipient in ("both", "b"):
            mapping["recipient-b"] = bytes(range(16))
        valid, claims, clean = verify_fixture(token, AUDIENCE, aead_key_resolver=mapping.get)
        assert valid and clean
        assert (501 in claims) == (recipient in ("both", "a"))
        assert ("region" in claims[503]) == (recipient in ("both", "b"))
        assert claims[503]["postal_code"] == "94188"
        assert claims[502] == [1549560720, 1612560720, 1674004740]


@pytest.mark.parametrize(
    "plaintext",
    [
        b"\xff",  # invalid CBOR
        cbor_utils.encode(FIRST_DISCLOSURE) + b"\x00",  # trailing item
        b"\x59\x00\x21" + FIRST_DISCLOSURE,  # non-preferred bstr length
        b"\x5f" + cbor_utils.encode(FIRST_DISCLOSURE) + b"\xff",  # indefinite bstr
    ],
)
def test_authenticated_but_malformed_plaintext_is_rejected(plaintext):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = bytes(12)
    ciphertext = AESGCM(DRAFT_KEY).encrypt(nonce, plaintext, b"")
    with pytest.raises(AeadDisclosureError):
        decrypt_disclosure([nonce, ciphertext[:-16], ciphertext[-16:]], DRAFT_KEY)


def test_nonempty_aad_is_not_accepted():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = bytes(12)
    ciphertext = AESGCM(DRAFT_KEY).encrypt(nonce, cbor_utils.encode(FIRST_DISCLOSURE), b"wrong aad")
    with pytest.raises(AeadDisclosureError, match="authentication"):
        decrypt_disclosure([nonce, ciphertext[:-16], ciphertext[-16:]], DRAFT_KEY)


def test_no_encrypted_header_passthrough(issued):
    assert decrypt_sd_cwt_disclosures(issued, None) == (issued, [])


def test_fixed_nonce_count_must_match(issued):
    with pytest.raises(ValueError, match="one entry"):
        encrypt_sd_cwt_disclosures(issued, [], [FIRST_DISCLOSURE], DRAFT_KEY, nonces=[])


class TestDraft09:
    @pytest.mark.parametrize("algorithm,key_length", [(1, 16), (2, 32), (29, 32)])
    def test_holder_selects_algorithm_without_changing_issuer_signature(
        self, issued, holder_key, disclosures, algorithm, key_length
    ):
        key = bytes(range(key_length))
        presentation = SDCWTPresenter(holder_key).create_presentation(
            issued,
            list(disclosures.values()),
            [],
            AUDIENCE,
            encrypted_disclosures=[disclosures[501]],
            aead_key=key,
            aead_algorithm=algorithm,
            issued_at=issuance_time(issued),
        )
        outer = cbor_utils.get_tag_value(cbor_utils.decode(presentation))
        inner = cbor_utils.get_tag_value(
            cbor_utils.decode(cbor_utils.encode(cbor_utils.decode(outer[0])[13]))
        )
        original = cbor_utils.get_tag_value(cbor_utils.decode(issued))
        assert 172 not in cbor_utils.decode(inner[0])
        assert inner[1][172] == algorithm
        assert [inner[i] for i in (0, 2, 3)] == [original[i] for i in (0, 2, 3)]
        valid, claims, _ = verify_fixture(presentation, AUDIENCE, aead_key_resolver=lambda _: key)
        assert valid and claims[501] == "ABCD-123456"

    @pytest.mark.parametrize("algorithm", [-1, 65536, True, 1.5, "2", 3, 14, 28])
    def test_rejects_invalid_algorithm_id(self, issued, algorithm):
        from sd_cwt.aead import sd_aead_algorithm

        value = cbor_utils.decode(issued)
        value.value[1][172] = algorithm
        with pytest.raises(AeadDisclosureError):
            sd_aead_algorithm(cbor_utils.encode(value))

    def test_unsupported_algorithm_stays_opaque_and_resolver_is_not_called(self, issued):
        value = cbor_utils.decode(issued)
        value.value[1] = {172: 15, 171: [DRAFT_ENTRY]}
        opaque = cbor_utils.encode(value)

        def unexpected(_):
            pytest.fail("unsupported algorithm must not invoke key resolution")

        returned, remaining = decrypt_sd_cwt_disclosures(opaque, unexpected)
        assert returned == opaque and remaining == [DRAFT_ENTRY]

    def test_old_protected_algorithm_is_not_a_fallback(self, issued):
        value = cbor_utils.decode(issued)
        protected = cbor_utils.decode(value.value[0])
        protected[172] = 2
        value.value[0] = cbor_utils.encode(protected)
        with pytest.raises(AeadDisclosureError, match="unprotected"):
            decrypt_sd_cwt_disclosures(cbor_utils.encode(value), None)

    def test_resolver_can_select_by_nonce(self, issued, holder_key, disclosures):
        presentation = SDCWTPresenter(holder_key).create_presentation(
            issued,
            list(disclosures.values()),
            [],
            AUDIENCE,
            encrypted_disclosures=[disclosures[501]],
            aead_key=DRAFT_KEY,
            issued_at=issuance_time(issued),
        )
        nonce = _embedded_unprotected(presentation)[171][0][0]

        def resolver(entry, algorithm):
            assert algorithm == 1
            return {nonce: DRAFT_KEY}.get(entry[0])

        valid, claims, _ = verify_fixture(presentation, AUDIENCE, aead_entry_key_resolver=resolver)
        assert valid and claims[501] == "ABCD-123456"


@pytest.mark.parametrize("with_key", [False, True])
def test_native_rust_draft09_aes256_fixture(with_key):
    token = (FIXTURES / "aes256_aead.rust.cbor").read_bytes()
    valid, claims, clean = verify_fixture(
        token, AUDIENCE, aead_key_resolver=(lambda _: bytes(range(32))) if with_key else None
    )
    assert valid and clean
    assert (501 in claims) == with_key
    assert ("region" in claims[503]) == with_key
    assert claims[502] == ([1549560720, 1612560720, 1674004740] if with_key else [1674004740])


def test_draft09_published_first_disclosure_digest():
    from sd_cwt.redaction import hash_disclosure

    # Published -09 examples/first-blinded-hash.txt (corrected from -08).
    assert hash_disclosure(FIRST_DISCLOSURE).hex() == (
        "af375dc3fba1d082448642c00be7b2f7bb05c9d8fb61cfc230ddfdfb4616a693"
    )
