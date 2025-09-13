# Claude Context for SD-CWT Project

## Project Overview
This is an implementation of the IETF SPICE SD-CWT (Selective Disclosure CBOR Web Token) specification. The library provides cryptographic functions for creating and verifying selective disclosure tokens using CBOR encoding and COSE signatures.

## Key Components

### COSE Sign1 (`src/sd_cwt/cose_sign1.py`)
- Generic signing/verification functions that accept pluggable signers/verifiers
- `cose_sign1_sign()` - Creates COSE Sign1 messages
- `cose_sign1_verify()` - Verifies COSE Sign1 messages
- Protocol interfaces (`Signer`, `Verifier`) for external key management
- Example implementations (ES256Signer, ES256Verifier)

### COSE Keys (`src/sd_cwt/cose_keys.py`)
- `cose_key_generate()` - Generate COSE keys in CBOR format (defaults to ES256)
- Supports ES256, ES384, ES512, EdDSA algorithms via `CoseAlgorithm` enum
- Helper functions for key conversion and thumbprint calculation

### SD-CWT Issuer (`src/sd_cwt/issuer.py`)
- Creates selective disclosure tokens with redacted claims
- Uses EDN (Extended Diagnostic Notation) with redaction tags
- Manages disclosures and hashing

## Testing Commands
```bash
# Run all tests
.venv/bin/python -m pytest

# Run specific test files
.venv/bin/python -m pytest tests/test_cose_sign1.py -v
.venv/bin/python -m pytest tests/test_cose_keys.py -v

# Run with coverage
.venv/bin/python -m pytest --cov

# Type checking
.venv/bin/python -m mypy src/sd_cwt

# Linting
.venv/bin/python -m ruff check src/ tests/
```

## Code Style Guidelines
- Use type hints for all function signatures
- Follow existing patterns in the codebase
- Do not add comments unless explicitly requested
- Prefer editing existing files over creating new ones
- All public functions should be exposed in `src/sd_cwt/__init__.py`

## Important Notes
- The library uses cryptography.io for crypto operations
- CBOR encoding/decoding via cbor2 library
- Keys can be managed externally via Signer/Verifier protocols
- Focus on defensive security - do not create tools for offensive purposes

## Common Tasks
1. **Adding new algorithms**: Update `CoseAlgorithm` enum and implement in `cose_keys.py`
2. **New COSE functions**: Add to appropriate module and expose in `__init__.py`
3. **Testing**: Create corresponding test file in `tests/` directory
4. **Examples**: Add demo scripts to `examples/` directory

## Dependencies
- cbor2: CBOR encoding/decoding
- cryptography: Cryptographic operations
- cbor-diag: EDN parsing
- fido2: COSE key structures (legacy, being replaced)

## Project Structure
```
src/sd_cwt/
├── __init__.py         # Public API exports
├── cose_sign1.py       # COSE Sign1 implementation
├── cose_keys.py        # COSE key generation
├── issuer.py           # SD-CWT issuer
├── validation.py       # Token validation
├── edn_redaction.py    # EDN redaction handling
├── thumbprint.py       # Key thumbprint calculation
└── cli.py             # CLI interface
```