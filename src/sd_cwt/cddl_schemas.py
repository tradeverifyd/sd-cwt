"""CDDL schemas for SD-CWT and COSE Key Thumbprint specifications."""

# Complete draft-ietf-spice-sd-cwt-09 CDDL, spec commit 79c4381.
SD_CWT_CDDL = """
sd-cwt-types = sd-cwt-issued / kbt-cwt / sd-cwt-preissued

sd-cwt-issued = #6.18([
   protected: bstr .cbor sd-protected,
   sd-unprotected,
   payload: bstr .cbor sd-payload,
   signature: bstr
])

sd-protected = {
   &(typ: 16) ^ => 293 / "application/sd-cwt",
   &(alg: 1) ^ => int,
   ? &(kid: 4) ^ => bstr,
   ? &(CWT_Claims: 15) ^ => issued_sd_cwt_map,
   ? &(sd_alg: 170) ^ => int,        ; -16 for sha-256
   * label => safe_value
}

sd-unprotected = {
   ? &(sd_claims: 17) ^ => salted-array,
   ? &(sd_aead_encrypted_claims: 171) ^ => aead-encrypted-array,
   ? &(sd_aead: 172) ^ => uint .size 2,
   * label => safe_value
}

sd-payload = {
    ; standard claims
      &(iss: 1) ^ => tstr, ; "https://issuer.example"
    ? &(sub: 2) ^ => tstr, ; "https://holder.example"
    ? &(aud: 3) ^ => tstr, ; "https://verifier.example/app"
    ? &(exp: 4) ^ => secs, ; 1883000000
    ? &(nbf: 5) ^ => secs, ; 1683000000
    ? &(iat: 6) ^ => secs, ; 1683000000
    ? &(cti: 7) ^ => bstr,
      &(cnf: 8) ^ => safe_map, ; key confirmation
    ? &(vct: 11) ^ => bstr,
    ? &(cnonce: 39) ^ => bstr,
    ;
    ? redacted_claim_keys ^ => [ * bstr ],
    * label => issued_sd_cwt_value
}

kbt-cwt = #6.18([
   protected: bstr .cbor kbt-protected,
   kbt-unprotected,
   payload: bstr .cbor kbt-payload,
   signature: bstr
])

kbt-protected = {
   &(typ: 16) ^ => 294 / "application/kb+cwt",
   &(alg: 1) ^ => int,
   &(kcwt: 13) ^ => sd-cwt-issued,
   * label => safe_value
}

kbt-unprotected = {
   * label => safe_value
}

kbt-payload = {
      &(aud: 3) ^ => tstr,  ; "https://verifier.example/app"
      time-or-cti-claims,
    ? &(cnonce: 39) ^ => bstr,
    * label => safe_value
}

time-or-cti-claims = (
  ; Requires either time claims that include an iat OR a cti claim.
  ; Note that in CDDL, the // operator has very low precedence (see
  ; Section 2.2.2 of RFC 8610)
  ;
  ; It is possible to have both a cti and time claims, but
  ; time-or-cti-claims insures at least cti or iat is present
  ? &(exp: 4) ^ => secs,
  ? &(nbf: 5) ^ => secs,
    &(iat: 6) ^ => secs  //
    &(cti: 7) ^ => bstr
)
sd-cwt-preissued = #6.18([
   protected: bstr .cbor sd-protected,
   sd-unprotected,
   payload: bstr .cbor preissuance_map,
   signature: bstr
])

; CWT claim legal values only
safe_map = { * label => safe_value }

safe_value =
  int / tstr / bstr /
  [ * safe_value ] /
  safe_map /
  #6.<safe_tag>(safe_value) / #7.<safe_simple> / float


; legal values in issued SD-CWT
issued_sd_cwt_map = {
    ? redacted_claim_keys ^ => [ * bstr ],
    * label => issued_sd_cwt_value
}

issued_array_element = redacted_claim_element / issued_sd_cwt_value

issued_sd_cwt_value =
  int / tstr / bstr /
  [ * issued_array_element ] /
  issued_sd_cwt_map /
  #6.<safe_tag>(issued_sd_cwt_value) / #7.<safe_simple> / float


; legal values in claim set sent to Issuer
preissuance_label = label /
                    #6.<TO_BE_REDACTED_TAGNUM>(label) /
                    #6.<TO_BE_DECOY_TAGNUM>(uint .gt 0)

preissuance_map = { * preissuance_label => preissuance_value }

preissuance_value =
  int / tstr / bstr /
  [ * preissuance_value ] /
  preissuance_map /
  #6.<safe_tag>(preissuance_value) / #7.<safe_simple> / float

; CBOR tag number for wrapping to-be-redacted keys or elements
TO_BE_REDACTED_TAGNUM = 58
; CBOR tag number for indicating a decoy value is to be inserted here
TO_BE_DECOY_TAGNUM = 62

label = int / tstr .size (1..255)
safe_tag = uint .ne (TO_BE_REDACTED_TAGNUM /
                     TO_BE_DECOY_TAGNUM /
                     REDACTED_ELEMENT_TAGNUM)

; exclude reserved simple values (24 through 31) from Table 4 of
; RFC 8949, and redacted keys array
safe_simple =  0..23 / 32..58 / 60..255
secs = int / float53
float53 = -9007199254740992.0..9007199254740992.0 ; from 2^53 to 2^53

salted-array = [ +bstr-encoded-salted ]

bstr-encoded-salted = bstr .cbor salted-entry
salted-entry = salted-claim / salted-element / decoy
salted-claim = [
  bstr .size 16,     ; 128-bit salt
  any,               ; Claim Value
  (int / text)       ; Claim Key
]
salted-element = [
  bstr .size 16,     ; 128-bit salt
  any                ; Claim Value
]
decoy = [
  bstr .size 16      ; 128-bit salt
]

aead-encrypted-array = [ +aead-encrypted ]
aead-encrypted = [
  bstr,              ; nonce of N_MIN octets
  bstr,              ; the encryption ciphertext output of a
                     ;   bstr-encoded-salted
  bstr,              ; the corresponding authentication tag
  ?aead-key-context  ; optional context to select the correct key
]
aead-key-context = uint / tstr / thumbprint
thumbprint = bstr    ; a COSE key thumprint; redacted_claim_keys is used as a map key. The corresponding value is
; an array of Redacted Claim Hashes whose corresponding unredacted map
; keys and values are in the same map.
redacted_claim_keys = #7.59  ; CBOR simple value 59

; CBOR tag for wrapping a redacted element in an array
REDACTED_ELEMENT_TAGNUM = 60

; redacted_claim_element is used in CDDL payloads that contain
; array elements that are meant to be redacted.
redacted_claim_element = #6.<REDACTED_ELEMENT_TAGNUM>( bstr )

"""

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
