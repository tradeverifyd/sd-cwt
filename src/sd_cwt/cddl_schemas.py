"""CDDL schemas for SD-CWT and COSE Key Thumbprint specifications."""

# SD-CWT CDDL Schema - Exact specification from draft-ietf-spice-sd-cwt-04 Appendix A
SD_CWT_CDDL = """
; Complete CDDL Schema from draft-ietf-spice-sd-cwt-04 Appendix A

sd-cwt-types = sd-cwt-issued / kbt-cwt

sd-cwt-issued = #6.18([
   protected: bstr .cbor sd-protected,
   sd-unprotected,
   payload: bstr .cbor sd-payload,
   signature: bstr
])

kbt-cwt = #6.18([
   protected: bstr .cbor kbt-protected,
   kbt-unprotected,
   payload: bstr .cbor kbt-payload,
   signature: bstr
])

sd-protected = {
   &(typ: 16) ^ => "application/sd-cwt" / TBD11,
   &(alg: 1) ^ => int,
   &(sd_alg: TBD2) ^ => int,        ; -16 for sha-256
   ? &(sd_aead: TBD7) ^ => uint .size 2
   * key => any
}

kbt-protected = {
   &(typ: 16) ^ => "application/kb+cwt" / TBD12,
   &(alg: 1) ^ => int,
   &(kcwt: 13) ^ => sd-cwt-issued,
   * key => any
}

sd-unprotected = {
   ? &(sd_claims: TBD1) ^ => salted-array,
   ? &(sd_aead_encrypted_claims: TBD6) ^ => aead-encrypted-array,
   * key => any
}

kbt-unprotected = {
   * key => any
}

sd-payload = {
    ; standard claims
      &(iss: 1) ^ => tstr, ; "https://issuer.example"
    ? &(sub: 2) ^ => tstr, ; "https://device.example"
    ? &(aud: 3) ^ => tstr, ; "https://verifier.example/app"
    ? &(exp: 4) ^ => int,  ; 1883000000
    ? &(nbf: 5) ^ => int,  ; 1683000000
    ? &(iat: 6) ^ => int,  ; 1683000000
    ? &(cti: 7) ^ => bstr,
      &(cnf: 8) ^ => { * key => any }, ; key confirmation
    ? &(cnonce: 39) ^ => bstr,
    ;
    ? &(redacted_claim_keys: REDACTED_KEYS) ^ => [ * bstr ],
    * key => any
}

kbt-payload = {
      &(aud: 3) ^ => tstr, ; "https://verifier.example/app"
    ? &(exp: 4) ^ => int,  ; 1883000000
    ? &(nbf: 5) ^ => int,  ; 1683000000
      &(iat: 6) ^ => int,  ; 1683000000
    ? &(cnonce: 39) ^ => bstr,
    * key => any
}

salted-array = [ +bstr .cbor salted ]
salted = salted-claim / salted-element / decoy
salted-claim = [
  bstr .size 16,     ; 128-bit salt
  any,               ; claim value
  (int / text)       ; claim name
]
salted-element = [
  bstr .size 16,     ; 128-bit salt
  any                ; claim value
]
decoy = [
  bstr .size 16      ; 128-bit salt
]

aead-encrypted-array = [ +aead-encrypted ]
aead-encrypted = [
  bstr .size 16,     ; 128-bit nonce
  bstr,              ; the encryption ciphertext output of a
                     ;   bstr-encoded-salted
  bstr               ; the corresponding authentication tag
]

header_map = {
    * key => any
}
empty_or_serialized_map = bstr .cbor header_map / bstr .size 0

key = int / text
TBD1 = 17
TBD2 = 18
TBD6 = 19
TBD7 = 20
TBD11 = 298
TBD12 = 299

; REDACTED_KEYS is to be used in CDDL payloads that are meant to
; convey that a map key is redacted.
REDACTED_KEYS = #7.59  ; #7.<TBD4>
;TBD4 = 59          ; for CBOR simple value 59

; redacted_claim_element is to be used in CDDL payloads that contain
; array elements that are meant to be redacted.
redacted_claim_element = #6.60( bstr .size 16 )  ; #6.<TBD5>(bstr)
;TBD5 = 60; CBOR tag wrapping redacted_claim_element

; Confirmation methods
cnf = {
    ; COSE_Key confirmation
    ? 1 => COSE_Key,  ; COSE_Key
    ? 3 => bstr,      ; kid (key identifier)
    * int => any
}

; Disclosure array format
disclosure = [
    bstr,   ; salt (base64url encoded)
    tstr,   ; claim name
    any     ; claim value
]

; SD-CWT with disclosures (for holder)
sd-cwt-with-disclosures = {
    "sd_cwt" => bstr,  ; The SD-CWT token
    "disclosures" => [* bstr]  ; Array of base64url encoded disclosures
}

; Presentation format (what holder sends to verifier)
sd-cwt-presentation = {
    "sd_cwt" => bstr,  ; The SD-CWT token
    "disclosures" => [* bstr],  ; Selected disclosures to reveal
    ? "kb_jwt" => bstr  ; Key binding JWT (if holder binding is used)
}
"""

# COSE Key Thumbprint CDDL Schema based on RFC 9679
COSE_KEY_THUMBPRINT_CDDL = """
; COSE Key Thumbprint CDDL Schema (RFC 9679)

; COSE Key structure for thumbprint computation
COSE_Key = {
    1 => kty,           ; Key Type
    ? 2 => kid,         ; Key ID (excluded from thumbprint)
    ? 3 => alg,         ; Algorithm (excluded from thumbprint)
    ? 4 => key_ops,     ; Key Operations (excluded from thumbprint)
    ? 5 => base_iv,     ; Base IV (excluded from thumbprint)
    * int => any        ; Additional parameters based on kty
}

kty = int .size 1
kid = bstr
alg = int
key_ops = [+ (int / tstr)]
base_iv = bstr

; OKP Key Type (kty = 1)
okp-thumbprint = {
    1 => 1,        ; kty: OKP
    -1 => crv,     ; curve
    -2 => x        ; x coordinate (public key)
}

; EC2 Key Type (kty = 2)
ec2-thumbprint = {
    1 => 2,        ; kty: EC2
    -1 => crv,     ; curve
    -2 => x,       ; x coordinate
    -3 => y        ; y coordinate
}

; RSA Key Type (kty = 3)
rsa-thumbprint = {
    1 => 3,        ; kty: RSA
    -1 => n,       ; modulus
    -2 => e        ; public exponent
}

; Symmetric Key Type (kty = 4)
symmetric-thumbprint = {
    1 => 4,        ; kty: Symmetric
    -1 => k        ; key value
}

; Curve identifiers
crv = int .size 1
; 1 = P-256
; 2 = P-384
; 3 = P-521
; 4 = X25519
; 5 = X448
; 6 = Ed25519
; 7 = Ed448

; Coordinate and key values
x = bstr
y = bstr
n = bstr
e = bstr
k = bstr

; Thumbprint URI format
thumbprint-uri = tstr .regexp "urn:ietf:params:oauth:ckt:(sha256|sha384|sha512):[A-Za-z0-9_-]+"

; Canonical COSE Key for thumbprint
; Only required members included, sorted by label
canonical-cose-key = okp-thumbprint / ec2-thumbprint / rsa-thumbprint / symmetric-thumbprint
"""

# CDDL for verified claims (closed claimset after verification)
VERIFIED_CLAIMS_CDDL = """
; Verified Claims CDDL Schema
; This schema validates the closed claimset that a verifier obtains
; after successfully validating an SD-CWT presentation.
;
; Using wildcard approach to work around zcbor limitations with complex schemas

verified-claims = {
    ; Standard CWT claims (mandatory-to-disclose)
    1: tstr,        ; iss - issuer (always mandatory)
    ? 2: tstr,      ; sub - subject (can be disclosed)
    ? 3: tstr,      ; aud - audience (mandatory if present)
    ? 4: int,       ; exp - expiration (mandatory if present)
    ? 5: int,       ; nbf - not before (mandatory if present)
    ? 6: int,       ; iat - issued at (mandatory if present)
    ? 7: bstr,      ; cti - CWT ID (mandatory if present)
    8: cnf-claim,   ; cnf - confirmation (always mandatory)
    ? 39: bstr,     ; cnonce - client nonce (mandatory if present)

    ; Allow any string keys with any value types (custom claims)
    * tstr => any,
}

; Confirmation claim structure - only validate well-formed COSE keys
cnf-claim = {
    ? 1: cose-key,        ; Full COSE key (well-formed)
    ? 3: bstr,            ; COSE key thumbprint
}

; Well-formed COSE key structure
cose-key = {
    1: int,               ; kty - key type (required)
    ? 3: int,             ; alg - algorithm
    ? -1: int,            ; crv - curve (for EC keys)
    ? -2: bstr,           ; x - x coordinate
    ? -3: bstr,           ; y - y coordinate (for EC2 keys)
    ? -4: bstr,           ; d - private key (should not be present in cnf)
}
"""

# Combined CDDL for full SD-CWT with COSE keys
COMBINED_CDDL = (
    """
; Combined CDDL for SD-CWT with COSE Key support

"""
    + SD_CWT_CDDL
    + """

; COSE Key definition for use in cnf claim
"""
    + COSE_KEY_THUMBPRINT_CDDL
    + """

; Verified claims schema for verifier validation
"""
    + VERIFIED_CLAIMS_CDDL
)

# Additional CDDL for test vectors
TEST_VECTOR_CDDL = """
; Test Vector CDDL Schema

test-vector = {
    "description" => tstr,
    "input" => test-input,
    "output" => test-output,
    ? "intermediate" => intermediate-values
}

test-input = {
    "key" => COSE_Key,
    ? "claims" => sd-cwt-claims,
    ? "hash_alg" => tstr,
    ? "disclosures" => [* disclosure]
}

test-output = {
    ? "thumbprint" => bstr,
    ? "thumbprint_uri" => tstr,
    ? "sd_cwt" => bstr,
    ? "canonical_cbor" => bstr
}

intermediate-values = {
    ? "canonical_key" => bstr,
    ? "disclosure_hashes" => [* bstr],
    ? "protected_header" => bstr
}
"""
