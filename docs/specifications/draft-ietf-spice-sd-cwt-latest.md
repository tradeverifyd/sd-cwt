# SD-CWT: Selective Disclosure CBOR Web Token (Latest Draft)

This is the latest editors draft from: https://github.com/ietf-wg-spice/draft-ietf-spice-sd-cwt/blob/main/draft-ietf-spice-sd-cwt.md

## Key Elements

### CBOR Diagnostic Notation Example of a Standard CWT:
```cbor
{
  1: "https://issuer.example",
  2: "https://device.example", 
  4: 1725330600,
  5: 1725243840,
  6: 1725244200,
  8: {
    1: {
      1: 2,  // Key type
      -1: 1, // Curve
      -2: h'8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d',
      -3: h'4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'
    }
  },
  500: true,
  501: "ABCD-123456",
  502: [1549560720, 1612498440, 1674004740],
  503: {
    "country": "us",
    "region": "ca", 
    "postal_code": "94188"
  }
}
```

### Redaction Tags:
- **Redacted Claim Key Tag**: Simple value TBD4 (requested value 59)
- **Redacted Claim Element Tag**: Tag 60

### Key Specification Characteristics:
- Uses COSE_Sign1 with asymmetric signature
- 128-bit cryptographically random salt for each disclosed claim
- Supports partial or full claim disclosure
- Includes key binding token (SD-KBT) for proof of possession
- Flexible mechanism for selectively disclosing claims in CBOR Web Tokens while maintaining cryptographic integrity

### Implementation Notes:
- SD-CWT uses EDN and CDDL and CBOR, not JSON
- EDN is used to convey the to-be-issued claimsets with the to-be-redacted tag
- Test cases must match the specification exactly