# SD-CWT CLI Guide: Steel Mill Rebar Batch Credentials

A comprehensive guide for using the SD-CWT (Selective Disclosure for CWT) command-line interface to create, issue, and present steel mill rebar batch verifiable credentials with selective disclosure capabilities for customs clearance.

## Overview

SD-CWT enables selective disclosure of claims in verifiable credentials, allowing steel mills to issue batch credentials to customs brokers who can then selectively disclose information to US Customs while maintaining cryptographic integrity. This guide covers the complete workflow from key generation to credential presentation using CBOR, EDN, and CDDL formats.

## Table of Contents

1. [Key Generation](#key-generation)
2. [Credential Issuance](#credential-issuance)
3. [Credential Presentation](#credential-presentation)
4. [Verification](#verification)
5. [Examples](#examples)

## Key Generation

### Generate Steel Mill QA Officer Keys

#### Step 1: Generate Private Key

```bash
# Generate EC2 P-256 steel mill QA officer private key
sd-cwt-cli keygen --type issuer --algorithm ES256 --output steel-mill-qa-private-key.cbor

# Generate with specific key ID
sd-cwt-cli keygen --type issuer --algorithm ES256 --key-id "steel-mill-qa-officer" --output steel-mill-qa-private-key.cbor
```

#### Step 2: Derive Public Key

```bash
# Derive public key from private key
sd-cwt-cli keygen --derive-public --private-key steel-mill-qa-private-key.cbor --output steel-mill-qa-public-key.cbor
```

### Generate Customs Broker Keys

#### Step 1: Generate Private Key

```bash
# Generate EC2 P-256 customs broker private key
sd-cwt-cli keygen --type holder --algorithm ES256 --output customs-broker-private-key.cbor

# Generate with specific key ID
sd-cwt-cli keygen --type holder --algorithm ES256 --key-id "customs-broker-import-logistics" --output customs-broker-private-key.cbor
```

#### Step 2: Derive Public Key

```bash
# Derive public key from private key
sd-cwt-cli keygen --derive-public --private-key customs-broker-private-key.cbor --output customs-broker-public-key.cbor
```

## Key Management Overview

### Key Types and Usage

| Role | Key Type | Usage | Security |
|------|----------|-------|----------|
| **Steel Mill QA Officer** | Private Key | Signing credentials during issuance | Keep secret, never share |
| **Steel Mill QA Officer** | Public Key | Verifying credentials during presentation | Can be shared publicly |
| **Customs Broker** | Private Key | Holder binding and presentation | Keep secret, never share |
| **Customs Broker** | Public Key | Embedded in credential for holder binding | Can be shared publicly |

### Key File Naming Convention

- **Private keys**: `*-private-key.cbor` (e.g., `steel-mill-qa-private-key.cbor`)
- **Public keys**: `*-public-key.cbor` (e.g., `steel-mill-qa-public-key.cbor`)
- **Key generation** creates separate files for private and public keys
- **Issuance** uses the issuer's private key and holder's public key
- **Verification** uses the issuer's public key
- **Presentation** uses the holder's private key for holder binding

## Credential Issuance

### Basic Issuance

Create a rebar batch credential with selective disclosure capabilities using EDN (Extended Diagnostic Notation) with redaction tags:

```bash
# Issue rebar batch credential with redacted claims
sd-cwt-cli issue \
  --issuer-key steel-mill-qa-private-key.cbor \
  --holder-key customs-broker-public-key.cbor \
  --claims rebar-batch-credential.edn \
  --output rebar-mill-test-certificate.cbor
```

**Key Usage**:
- `--issuer-key`: Steel mill QA officer's **private key** (for signing the credential)
- `--holder-key`: Customs broker's **public key** (embedded in the credential for holder binding)

### EDN Claims Format

The claims file uses EDN with redaction tags to mark which rebar batch claims can be selectively disclosed. **Tag 59 indicates that a claim is disclosable by the holder** - meaning the customs broker can choose whether to reveal it during presentation.

```edn
{
  ; Mandatory claims (always disclosed)
  1: "https://steel-mill-corp.com/qa",        ; iss - steel mill QA officer
  2: "https://customs-broker-import.com",     ; sub - customs broker
  6: 1725244200,                              ; iat - issued at
  8: {                                        ; cnf - confirmation (holder binding)
    1: {                                      ; COSE_Key
      1: 2,                                   ; kty: EC2
      -1: 1,                                  ; crv: P-256
      -2: h'8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d',
      -3: h'4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'
    }
  },
  11: "https://steel.consortium.example/rebar-mill-test-certificate.cddl",  ; vct - Verifiable Credential Type

  ; Possible to disclose claims (marked with redaction tags)
  "heat_number": 59("H240115-001"),
  "chemical_composition": 59({
    "carbon": 0.25,
    "manganese": 1.20,
    "phosphorus": 0.040,
    "sulfur": 0.050
  }),
  "production_cost": 59(850.75),
  "quality_test_results": 59({
    "tensile_strength": 420,
    "yield_strength": 350,
    "elongation": 18.5,
    "test_date": "2024-01-15"
  }),

  ; Always disclosed claims (no redaction tags)
  "credential_type": "rebar_batch_credential",
  "batch_id": "BATCH-2024-001",
  "production_date": "2024-01-15",
  "steel_grade": "ASTM A615 Grade 60",
  "mill_location": "Pittsburgh, PA",
  "qa_officer": "John Smith",
  "qa_certification": "AWS-CWI-2024"
}
```

**Key Points:**
- Claims with `59(value)` are disclosable by the holder (see explanation above)
- Claims without redaction tags are **always disclosed** - visible to all verifiers (US Customs)
- Mandatory claims (iss, sub, iat, cnf, vct) are always disclosed per specification
- The `vct` claim (claim key 11) identifies the type of verifiable credential

## Credential Presentation

### Selective Disclosure

The customs broker chooses which of the "possible to disclose" claims to reveal. The EDN format below shows exactly what the verifier will see after selective disclosure, with all undisclosed claims removed:

```bash
# Present credential with selective disclosure using direct claim specification
sd-cwt-cli present \
  --credential rebar-mill-test-certificate.cbor \
  --holder-key customs-broker-private-key.cbor \
  --audience "https://us-customs.example" \
  --nonce "1234567890" \
  --output rebar-presentation.cbor \
  --disclosure <<EOF {
  1: "https://steel-mill-corp.example/qa",        ; iss - steel mill QA officer
  2: "https://customs-broker-import.example",     ; sub - customs broker  
  6: 1725244200,                                  ; iat - issued at
  8: {                                            ; cnf - confirmation
    1: {
      1: 2,                                       ; kty: EC2
      -1: 1,                                      ; crv: P-256
      -2: h'8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d',
      -3: h'4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'
    }
  },
  11: "https://steel.consortium.example/rebar-mill-test-certificate.cddl",  ; vct
  "batch_id": "BATCH-2024-001",
  "production_date": "2024-01-15", 
  "steel_grade": "ASTM A615 Grade 60",
  "mill_location": "Pittsburgh, PA",
  "qa_officer": "John Smith",
  "qa_certification": "AWS-CWI-2024",
  "heat_number": "H240115-001",                   ; disclosed by customs broker
  "chemical_composition": {                       ; disclosed by customs broker
    "carbon": 0.25,
    "manganese": 1.20,
    "phosphorus": 0.040,
    "sulfur": 0.050
  }
  ; Note: production_cost and quality_test_results are NOT present
  ; (customs broker chose not to disclose these sensitive claims)
}
EOF
  
```

### Holder's Selected Disclosures

The `--disclose` parameter accepts one or more claim names that the holder chooses to reveal. In this example, the customs broker chooses to disclose:

- `heat_number`: The specific heat number for traceability
- `chemical_composition`: Detailed chemical analysis for quality verification

**Claims that will be disclosed:**
- **Always disclosed** (mandatory): `iss`, `sub`, `iat`, `cnf`, `vct`, `batch_id`, `production_date`, `steel_grade`, `mill_location`, `qa_officer`, `qa_certification`
- **Holder selected**: `heat_number`, `chemical_composition`
- **Not disclosed** (holder's choice): `production_cost`, `quality_test_results`

**Resulting disclosure will show:**
```edn
{
  1: "https://steel-mill-corp.example/qa",        ; iss - always disclosed
  2: "https://customs-broker-import.example",     ; sub - always disclosed  
  6: 1725244200,                                  ; iat - always disclosed
  8: {                                            ; cnf - always disclosed
    1: {
      1: 2,                                       ; kty: EC2
      -1: 1,                                      ; crv: P-256
      -2: h'8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d',
      -3: h'4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'
    }
  },
  11: "https://steel.consortium.example/rebar-mill-test-certificate.cddl",  ; vct - always disclosed
  "batch_id": "BATCH-2024-001",                  ; always disclosed
  "production_date": "2024-01-15",               ; always disclosed
  "steel_grade": "ASTM A615 Grade 60",           ; always disclosed
  "mill_location": "Pittsburgh, PA",             ; always disclosed
  "qa_officer": "John Smith",                    ; always disclosed
  "qa_certification": "AWS-CWI-2024",            ; always disclosed
  "heat_number": "H240115-001",                  ; holder chose to disclose
  "chemical_composition": {                      ; holder chose to disclose
    "carbon": 0.25,
    "manganese": 1.20,
    "phosphorus": 0.040,
    "sulfur": 0.050
  }
  ; Note: production_cost and quality_test_results are NOT included
  ; (holder chose not to disclose these sensitive claims)
}
```

**Key Benefits of direct claim specification:**
- **Simple and direct**: Specify only the claim names you want to disclose
- **No file management**: No need to create and maintain separate EDN files
- **Clear intent**: Explicitly shows which claims the holder chooses to reveal
- **Flexible**: Easy to modify disclosure choices for different presentations

### Presentation Structure

The presentation contains:
- The SD-CWT token (with redacted claims)
- Selected disclosures (only the claims the customs broker chose to reveal)
- Key binding token (if holder binding is used)

```edn
{
  "sd_cwt" => h'...',  ; The SD-CWT token (CBOR bytes)
  "disclosures" => [   ; Array of base64url encoded disclosures
    h'...',            ; heat_number disclosure
    h'...'             ; chemical_composition disclosure
  ],
  "kb_jwt" => h'...'   ; Key binding JWT (if holder binding is used)
}
```

**What gets disclosed:**
- **Always disclosed**: `iss`, `sub`, `iat`, `cnf`, `vct`, `batch_id`, `production_date`, `steel_grade`, `mill_location`, `qa_officer`, `qa_certification`
- **Chosen to disclose**: `heat_number`, `chemical_composition` (customs broker's choice)
- **Kept private**: `production_cost`, `quality_test_results` (customs broker chose not to disclose)

## Verification

### Verify Presentation

```bash
# Verify a presentation
sd-cwt-cli verify \
  --presentation rebar-presentation.cbor \
  --issuer-key steel-mill-qa-public-key.cbor \
  --output verified-claims.cbor
```

**Key Usage**:
- `--issuer-key`: Steel mill QA officer's **public key** (for verifying the credential signature)

### Verified Claims

After verification, US Customs receives the complete set of disclosed claims in CBOR format:

```edn
{
  1: "https://steel-mill-corp.example/qa",        ; iss - steel mill QA officer
  2: "https://customs-broker-import.example",     ; sub - customs broker
  6: 1725244200,                              ; iat - issued at
  8: {                                        ; cnf - confirmation
    1: {
      1: 2,                                   ; kty: EC2
      -1: 1,                                  ; crv: P-256
      -2: h'8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d',
      -3: h'4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'
    }
  },
  11: "https://steel.consortium.example/rebar-mill-test-certificate.cddl",                 ; vct - Verifiable Credential Type
  "batch_id": "BATCH-2024-001",
  "production_date": "2024-01-15",
  "steel_grade": "ASTM A615 Grade 60",
  "mill_location": "Pittsburgh, PA",
  "qa_officer": "John Smith",
  "qa_certification": "AWS-CWI-2024",
  "heat_number": "H240115-001",
  "chemical_composition": {
    "carbon": 0.25,
    "manganese": 1.20,
    "phosphorus": 0.040,
    "sulfur": 0.050
  }
}
```
