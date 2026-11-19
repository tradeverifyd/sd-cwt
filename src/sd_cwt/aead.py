"""AEAD encrypted disclosures (draft-ietf-spice-sd-cwt-09, Section "Encrypted Disclosures").

A Holder MAY move some of the Salted Disclosed Claims it presents out of
``sd_claims`` (17) and into ``sd_aead_encrypted_claims`` (171), encrypted to an
inner Verifier with a symmetric key agreed out of band. The AEAD algorithm is
taken from ``sd_aead`` (172) in the SD-CWT unprotected header, defaulting to
AEAD_AES_128_GCM.

The plaintext is the full CBOR encoding of ``bstr .cbor salted-entry`` -- the
byte string header included -- which is also the input to the Redacted Claim
Hash. The draft's example (aead-claim-array.edn) only decrypts under that
reading. The associated data is empty.
"""

import os
from collections.abc import Iterable
from typing import Any, Callable, Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from . import cbor_utils

SD_CLAIMS = 17
SD_AEAD_ENCRYPTED_CLAIMS = 171
SD_AEAD = 172

AEAD_AES_128_GCM = 1
AEAD_AES_256_GCM = 2
AEAD_CHACHA20_POLY1305 = 29

DEFAULT_AEAD = AEAD_AES_128_GCM
FORBIDDEN_AEAD = set(range(3, 15)) | {18, 19, 21, 22, 24, 25, 27, 28}

TAG_LENGTH = 16

# IANA AEAD id -> (key length, N_MIN nonce length, implementation)
_ALGORITHMS: dict[int, tuple[int, int, Any]] = {
    AEAD_AES_128_GCM: (16, 12, AESGCM),
    AEAD_AES_256_GCM: (32, 12, AESGCM),
    AEAD_CHACHA20_POLY1305: (32, 12, ChaCha20Poly1305),
}

KeyContext = Union[int, str, bytes]
AeadKeyResolver = Callable[[Optional[KeyContext]], Union[None, bytes, Iterable[bytes]]]


class AeadDisclosureError(ValueError):
    """Raised when an encrypted disclosure is malformed or fails to decrypt."""


def _algorithm(alg: int) -> tuple[int, int, Any]:
    if type(alg) is not int or alg not in _ALGORITHMS:
        raise AeadDisclosureError(f"unsupported AEAD algorithm: {alg!r}")
    return _ALGORITHMS[alg]


def _cipher(alg: int, key: bytes) -> Any:
    key_length, _nonce_length, impl = _algorithm(alg)
    if not isinstance(key, bytes) or len(key) != key_length:
        raise AeadDisclosureError(f"AEAD algorithm {alg} requires a {key_length} byte key")
    return impl(key)


def _check_key_context(key_context: Any) -> None:
    if isinstance(key_context, bool) or not (
        (isinstance(key_context, int) and key_context >= 0) or isinstance(key_context, (str, bytes))
    ):
        raise AeadDisclosureError("aead-key-context must be a uint, tstr or bstr")


def encrypt_disclosure(
    disclosure: bytes,
    key: bytes,
    alg: int = DEFAULT_AEAD,
    nonce: Optional[bytes] = None,
    key_context: Optional[KeyContext] = None,
) -> list[Any]:
    """Encrypt one disclosure into an ``aead-encrypted`` array.

    Args:
        disclosure: CBOR-encoded salted-entry (an ``sd_claims`` element)
        key: Symmetric AEAD key
        alg: IANA AEAD algorithm id
        nonce: Nonce of N_MIN octets; random when omitted. Only fix it for test vectors.
        key_context: Optional context the receiver uses to select the key

    Returns:
        ``[nonce, ciphertext, tag]`` or ``[nonce, ciphertext, tag, key_context]``
    """
    _key_length, nonce_length, _impl = _algorithm(alg)
    cipher = _cipher(alg, key)
    if nonce is None:
        nonce = os.urandom(nonce_length)
    elif len(nonce) != nonce_length:
        raise AeadDisclosureError(f"AEAD algorithm {alg} requires a {nonce_length} byte nonce")

    plaintext = cbor_utils.encode(disclosure)
    sealed = cipher.encrypt(nonce, plaintext, b"")
    entry: list[Any] = [nonce, sealed[:-TAG_LENGTH], sealed[-TAG_LENGTH:]]
    if key_context is not None:
        _check_key_context(key_context)
        entry.append(key_context)
    return entry


def _check_entry(entry: Any, alg: int) -> None:
    params = _ALGORITHMS.get(alg)
    if not isinstance(entry, list) or len(entry) not in (3, 4):
        raise AeadDisclosureError("aead-encrypted must be [nonce, ciphertext, tag, ?key-context]")
    nonce, ciphertext, tag = entry[:3]
    if not all(isinstance(part, bytes) for part in (nonce, ciphertext, tag)):
        raise AeadDisclosureError("nonce, ciphertext and tag must be byte strings")
    if params is not None and len(nonce) != params[1]:
        raise AeadDisclosureError(f"nonce must be {params[1]} bytes")
    if (params is not None and len(tag) != TAG_LENGTH) or len(tag) < TAG_LENGTH:
        raise AeadDisclosureError(
            "tag must be at least 16 bytes (exactly 16 for supported algorithms)"
        )
    if alg in (34, 35, 36, 37) and len(tag) != 32:
        raise AeadDisclosureError("AEGIS X algorithms require 32-byte tags")
    if len(entry) == 4:
        _check_key_context(entry[3])


def decrypt_disclosure(entry: list[Any], key: bytes, alg: int = DEFAULT_AEAD) -> bytes:
    """Decrypt an ``aead-encrypted`` array back into an ``sd_claims`` element.

    Args:
        entry: ``[nonce, ciphertext, tag, ?key_context]``
        key: Symmetric AEAD key
        alg: IANA AEAD algorithm id

    Returns:
        The CBOR-encoded salted-entry, as it would appear in ``sd_claims``

    Raises:
        AeadDisclosureError: If the entry is malformed, authentication fails,
            or the plaintext is not exactly one byte string
    """
    _check_entry(entry, alg)
    nonce, ciphertext, tag = entry[:3]
    try:
        plaintext = _cipher(alg, key).decrypt(nonce, ciphertext + tag, b"")
    except InvalidTag as e:
        raise AeadDisclosureError("encrypted disclosure failed authentication") from e

    try:
        disclosure = cbor_utils.decode(plaintext)
    except ValueError as e:
        raise AeadDisclosureError(f"decrypted disclosure is not valid CBOR: {e}") from e
    if not isinstance(disclosure, bytes):
        raise AeadDisclosureError("decrypted disclosure must be a bstr .cbor salted-entry")
    if cbor_utils.encode(disclosure) != plaintext:
        raise AeadDisclosureError("decrypted disclosure is not preferred CBOR encoding")
    return disclosure


def _split_cose_sign1(sd_cwt: bytes) -> tuple[Any, list[Any]]:
    decoded = cbor_utils.decode(sd_cwt)
    value = cbor_utils.get_tag_value(decoded) if cbor_utils.is_tag(decoded) else decoded
    if not isinstance(value, list) or len(value) != 4 or not isinstance(value[1], dict):
        raise ValueError("Invalid COSE Sign1 structure")
    return decoded, list(value)


def _join_cose_sign1(decoded: Any, value: list[Any]) -> bytes:
    if cbor_utils.is_tag(decoded):
        return cbor_utils.encode(cbor_utils.create_tag(cbor_utils.get_tag_number(decoded), value))
    return cbor_utils.encode(value)


def sd_aead_algorithm(sd_cwt: bytes) -> int:
    """Return the AEAD algorithm for an SD-CWT: ``sd_aead`` (172) or the default."""
    _decoded, value = _split_cose_sign1(sd_cwt)
    protected = cbor_utils.decode(value[0]) if value[0] else {}
    if SD_AEAD in protected:
        raise AeadDisclosureError("draft-09 sd_aead must be in unprotected headers")
    alg = value[1].get(SD_AEAD, DEFAULT_AEAD)
    if type(alg) is not int or not 0 <= alg <= 65535:
        raise AeadDisclosureError("sd_aead must be a uint of at most two bytes")
    if alg in FORBIDDEN_AEAD:
        raise AeadDisclosureError("AEAD algorithm forbidden by draft-09 section 16.9")
    return alg


def encrypt_sd_cwt_disclosures(
    sd_cwt: bytes,
    disclosures: list[bytes],
    to_encrypt: list[bytes],
    key: bytes,
    key_context: Optional[KeyContext] = None,
    nonces: Optional[list[bytes]] = None,
    *,
    algorithm: Optional[int] = None,
) -> bytes:
    """Place disclosures in an SD-CWT, encrypting some of them (Holder side).

    Args:
        sd_cwt: The SD-CWT whose unprotected header is rewritten
        disclosures: Disclosures to carry in plaintext in ``sd_claims``
        to_encrypt: Disclosures to carry encrypted in ``sd_aead_encrypted_claims``
        key: Symmetric AEAD key shared with the inner Verifier
        key_context: Optional context added to each encrypted entry
        nonces: Optional fixed nonces, one per element of ``to_encrypt``; test vectors only
        algorithm: Holder-selected AEAD id; otherwise use the unprotected hint or default.

    Returns:
        The SD-CWT with both header parameters set. Either is omitted when it
        would be empty, since an empty array is invalid.
    """
    if nonces is not None and len(nonces) != len(to_encrypt):
        raise ValueError("nonces must have one entry per disclosure to encrypt")

    existing_algorithm = sd_aead_algorithm(sd_cwt)
    alg = existing_algorithm if algorithm is None else algorithm
    if to_encrypt:
        _algorithm(alg)
    decoded, value = _split_cose_sign1(sd_cwt)
    unprotected = dict(value[1])
    unprotected.pop(SD_CLAIMS, None)
    unprotected.pop(SD_AEAD_ENCRYPTED_CLAIMS, None)

    if disclosures:
        unprotected[SD_CLAIMS] = list(disclosures)
    if to_encrypt:
        unprotected[SD_AEAD] = alg
        unprotected[SD_AEAD_ENCRYPTED_CLAIMS] = [
            encrypt_disclosure(
                disclosure,
                key,
                alg=alg,
                nonce=nonces[i] if nonces is not None else None,
                key_context=key_context,
            )
            for i, disclosure in enumerate(to_encrypt)
        ]

    value[1] = unprotected
    return _join_cose_sign1(decoded, value)


def _candidate_keys(resolved: Union[None, bytes, Iterable[bytes]]) -> list[bytes]:
    if resolved is None:
        return []
    if isinstance(resolved, bytes):
        return [resolved]
    return list(resolved)


def decrypt_sd_cwt_disclosures(
    sd_cwt: bytes,
    key_resolver: Optional[AeadKeyResolver],
    *,
    entry_key_resolver: Optional[
        Callable[[list[Any], int], Union[None, bytes, Iterable[bytes]]]
    ] = None,
) -> tuple[bytes, list[list[Any]]]:
    """Decrypt ``sd_aead_encrypted_claims`` into ``sd_claims`` (Verifier side).

    The resolver is called with each entry's key context, or None, and returns
    a key, a list of candidate keys, or None when this Verifier holds no key.
    Entries without a key are returned undecrypted so they can be forwarded to
    an inner Verifier. An entry that a resolved key fails to open is an error:
    the tag is 16 bytes, so a forgery would otherwise go unnoticed.

    Args:
        sd_cwt: SD-CWT, possibly carrying ``sd_aead_encrypted_claims``
        key_resolver: Maps a key context to candidate keys
        entry_key_resolver: Optional (entry, algorithm) callback, overriding context lookup.

    Returns:
        Tuple of (SD-CWT with decrypted disclosures appended to ``sd_claims``,
        entries that could not be decrypted). The second SD-CWT keeps the
        undecrypted entries in ``sd_aead_encrypted_claims``.

    Raises:
        AeadDisclosureError: On an empty or malformed header, or a failed decryption
    """
    decoded, value = _split_cose_sign1(sd_cwt)
    unprotected = dict(value[1])
    alg = sd_aead_algorithm(sd_cwt)
    if SD_CLAIMS in unprotected and unprotected[SD_CLAIMS] == []:
        raise AeadDisclosureError("sd_claims MUST NOT be an empty array")
    if SD_AEAD_ENCRYPTED_CLAIMS not in unprotected:
        return sd_cwt, []

    entries = unprotected[SD_AEAD_ENCRYPTED_CLAIMS]
    if not isinstance(entries, list) or not entries:
        raise AeadDisclosureError("sd_aead_encrypted_claims must be a non-empty array")

    alg = sd_aead_algorithm(sd_cwt)
    decrypted: list[bytes] = []
    remaining: list[list[Any]] = []
    for entry in entries:
        _check_entry(entry, alg)
        if alg not in _ALGORITHMS:
            remaining.append(entry)
            continue  # draft-09 section 9: unsupported algorithms remain opaque
        key_context = entry[3] if len(entry) == 4 else None
        if entry_key_resolver is not None:
            keys = _candidate_keys(entry_key_resolver(entry, alg))
        else:
            keys = _candidate_keys(key_resolver(key_context)) if key_resolver else []
        if not keys:
            remaining.append(entry)
            continue
        for key in keys:
            try:
                decrypted.append(decrypt_disclosure(entry, key, alg))
                break
            except AeadDisclosureError:
                continue
        else:
            raise AeadDisclosureError("encrypted disclosure failed authentication")

    if decrypted:
        combined = list(unprotected.get(SD_CLAIMS, [])) + decrypted
        # Each disclosure consumes one Redacted Claim Hash. Do not silently
        # collapse duplicates when building the reconstruction lookup.
        if len(set(combined)) != len(combined):
            raise AeadDisclosureError("duplicate disclosure after AEAD decryption")
        unprotected[SD_CLAIMS] = combined
    if remaining:
        unprotected[SD_AEAD_ENCRYPTED_CLAIMS] = remaining
    else:
        del unprotected[SD_AEAD_ENCRYPTED_CLAIMS]

    value[1] = unprotected
    return _join_cose_sign1(decoded, value), remaining
