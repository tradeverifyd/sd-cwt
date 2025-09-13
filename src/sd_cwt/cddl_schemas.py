"""CDDL schemas for SD-CWT and COSE Key Thumbprint specifications."""

# SD-CWT CDDL Schema based on draft-ietf-spice-sd-cwt-04
SD_CWT_CDDL = """
; SD-CWT CDDL Schema (draft-ietf-spice-sd-cwt-04)

; Main SD-CWT structure (COSE Sign1)
sd-cwt = #6.18(COSE_Sign1)

COSE_Sign1 = [
    protected: bstr .cbor protected-header,
    unprotected: unprotected-header,
    payload: bstr .cbor sd-cwt-claims,
    signature: bstr
]

; Protected header must include algorithm
protected-header = {
    1 => int,  ; alg
    * int => any
}

; Unprotected header
unprotected-header = {
    * int => any
}

; SD-CWT Claims
sd-cwt-claims = {
    ; Standard CWT claims (using integer keys)
    ? 1 => tstr,  ; iss (issuer)
    ? 2 => tstr,  ; sub (subject)
    ? 3 => tstr,  ; aud (audience)
    ? 4 => int,   ; exp (expiration time)
    ? 5 => int,   ; nbf (not before)
    ? 6 => int,   ; iat (issued at)
    ? 7 => bstr,  ; cti (CWT ID)
    
    ; SD-CWT specific claims
    "_sd" => [* bstr],        ; Selective disclosure digests
    ? "_sd_alg" => tstr,      ; Hash algorithm (default: sha-256)
    ? "..." => bool,          ; Indicates undisclosed claims exist
    
    ; Confirmation claim for holder binding
    ? 8 => cnf,  ; cnf (confirmation)
    
    ; Additional claims
    * (int / tstr) => any
}

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

# Combined CDDL for full SD-CWT with COSE keys
COMBINED_CDDL = """
; Combined CDDL for SD-CWT with COSE Key support

""" + SD_CWT_CDDL + """

; COSE Key definition for use in cnf claim
""" + COSE_KEY_THUMBPRINT_CDDL

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