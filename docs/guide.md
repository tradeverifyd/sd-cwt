# SD-CWT CLI Guide

## Key Generation

Generate cryptographic keys for the issuer and holder.

```bash
/ Generate manufacturer private key /
sd-cwt-cli generate_key \
  --algorithm ES256 \
  --private-key issuer-private-key.cbor

/ Generate customs broker private key /
sd-cwt-cli generate_key \
  --algorithm ES256 \
  --private-key holder-private-key.cbor
```

## Credential Issuance

Issue a credential to the holder.

```bash
sd-cwt-cli issue_sd_cwt \
  --issuer-key issuer-private-key.cbor \
  --credential rebar-mill-test-certificate.cbor \
  --claims '{
  / iss: issuer /                        1: "https://steel-manufacturer.example",
  / sub: subject /                       2: "https://customs-broker.example",
  / iat: issued at /                     6: 1725244200,
  / cnf: confirmation /                  8: {
    / COSE Key /                           1: {
      / kty: EC2 /                         1: 2,
      / crv: P-256 /                       -1: 1,
      / x coordinate /                     -2: h'4a8cf2c9b1d8e7f6a5b9c3d2e1f0a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1',
      / y coordinate /                     -3: h'f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f0e1d2c3b9a5f6e7d8b1c9f2a84'
    }
  },
  / vct: credential type /               11: "https://steel.consortium.example/rebar/v1.cddl",
  / mandatory to disclose /              "production_date": "2024-01-15",
  / mandatory to disclose /              "steel_grade": "ASTM A615 Grade 60",
  / optional to disclose /               "heat_number": 59("H240115-001"),
  / optional to disclose /               "chemical_composition": 59({
    / carbon percentage /                  "carbon": 0.25,
    / manganese percentage /               "manganese": 1.20,
    / phosphorus percentage /              "phosphorus": 0.040,
    / sulfur percentage /                  "sulfur": 0.050
  }),
  / optional to disclose /               "production_cost": 59(850.75),
  / optional to disclose /               "quality_test_results": 59({
    / MPa /                                "tensile_strength": 420,
    / MPa /                                "yield_strength": 350,
    / percentage /                         "elongation": 18.5
  }),
  / optional to disclose /               "inspection_dates": 59([
    / initial inspection /                  1549560720,
    / quality check /                       60(1612498440),
    / final inspection /                    60(1674004740)
  ])
}'
```

## Credential Presentation

Present credential with the holder choosing to disclose specific claims.

```bash
sd-cwt-cli present_sd_cwt \
  --holder-key holder-private-key.cbor \
  --audience "https://customs.us.example" \
  --nonce "1234567890" \
  --credential rebar-mill-test-certificate.cbor \
  --presentation rebar-presentation.cbor \
  --disclosure '{
  / iss: issuer /                        1: "https://steel-manufacturer.example",
  / sub: subject /                       2: "https://customs-broker.example",
  / iat: issued at /                     6: 1725244200,
  / cnf: confirmation /                  8: {
    / COSE Key /                           1: {
      / kty: EC2 /                         1: 2,
      / crv: P-256 /                       -1: 1,
      / x coordinate /                     -2: h'4a8cf2c9b1d8e7f6a5b9c3d2e1f0a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1',
      / y coordinate /                     -3: h'f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f0e1d2c3b9a5f6e7d8b1c9f2a84'
    }
  },
  / vct: credential type /               11: "https://steel.consortium.example/rebar/v1.cddl",
  / mandatory to disclose /              "production_date": "2024-01-15",
  / mandatory to disclose /              "steel_grade": "ASTM A615 Grade 60",
  / chosen to disclose /                 "heat_number": "H240115-001",
  / chosen to disclose /                 "chemical_composition": {
    / carbon percentage /                  "carbon": 0.25,
    / manganese percentage /               "manganese": 1.20,
    / phosphorus percentage /              "phosphorus": 0.040,
    / sulfur percentage /                  "sulfur": 0.050
  },
  / chosen to disclose /                 "inspection_dates": [
    / initial inspection /                  1549560720,
    / quality check disclosed /             1612498440
    / final inspection withheld /
  ]
  / other claims have been redacted /
}'
```
