"""AEAD encrypted disclosures, draft-ietf-spice-sd-cwt-08 Section "Encrypted Disclosures"."""

import pytest

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

    def test_uses_sd_aead_from_the_protected_header(self, holder_key, disclosures) -> None:
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
        valid, claims, _ = _verifier().verify_presentation(
            kbt, AUDIENCE, aead_key_resolver=lambda ctx: DRAFT_KEY
        )
        assert valid and claims is not None
        assert claims[501] == "ABCD-123456"
        assert claims[501] == "ABCD-123456"
        assert claims["region"] == "ca"

    def test_verifier_without_the_key_still_verifies(self, issued, holder_key, disclosures):
        kbt = self._present(issued, holder_key, disclosures)
        valid, claims, _ = _verifier().verify_presentation(kbt, AUDIENCE)
        assert valid and claims is not None
        assert 501 not in claims
        assert claims["region"] == "ca"

    def test_wrong_key_rejects_the_presentation(self, issued, holder_key, disclosures):
        kbt = self._present(issued, holder_key, disclosures)
        valid, _claims, _ = _verifier().verify_presentation(
            kbt, AUDIENCE, aead_key_resolver=lambda ctx: OTHER_KEY
        )
        assert not valid

    def test_requires_a_key_to_encrypt(self, issued, holder_key, disclosures):
        with pytest.raises(ValueError, match="aead_key"):
            SDCWTPresenter(holder_key).create_presentation(
                sd_cwt=issued,
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
            disclosures=[],
            selected_disclosures=[],
            audience=AUDIENCE,
            encrypted_disclosures=[foreign],
            aead_key=DRAFT_KEY,
        )
        valid, _claims, _ = _verifier().verify_presentation(
            kbt, AUDIENCE, aead_key_resolver=lambda ctx: DRAFT_KEY
        )
        assert not valid
        valid, _claims, _ = _verifier().verify_presentation(kbt, AUDIENCE)
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

        valid, claims, _ = _verifier().verify_presentation(
            kbt, AUDIENCE, aead_key_resolver=lambda ctx: DRAFT_KEY
        )
        assert valid and claims is not None
        assert claims[501] == "ABCD-123456"
