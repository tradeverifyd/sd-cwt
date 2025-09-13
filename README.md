# SD-CWT: Selective Disclosure CWT Implementation

This is an experimental implementation of [draft-ietf-spice-sd-cwt](https://github.com/ietf-wg-spice/draft-ietf-spice-sd-cwt).

## Overview

SD-CWT (Selective Disclosure CBOR Web Token) is a specification that enables selective disclosure of claims within CBOR Web Tokens, allowing holders to reveal only specific claims to verifiers while maintaining the cryptographic integrity of the token.

## Links

- **IETF Working Group Repository**: [https://github.com/ietf-wg-spice/draft-ietf-spice-sd-cwt](https://github.com/ietf-wg-spice/draft-ietf-spice-sd-cwt)
- **IETF Datatracker**: [https://datatracker.ietf.org/doc/draft-ietf-spice-sd-cwt/](https://datatracker.ietf.org/doc/draft-ietf-spice-sd-cwt/)
- **Implemented Internet-Draft**: [draft-ietf-spice-sd-cwt-04](https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt-04)

## Installation

### Install from GitHub using uv

```bash
# Install directly from GitHub
uv pip install git+https://github.com/tradeverifyd/sd-cwt.git

# Or add to your project
uv add git+https://github.com/tradeverifyd/sd-cwt.git
```

### Install for development

```bash
# Clone the repository
git clone https://github.com/tradeverifyd/sd-cwt.git
cd sd-cwt

# Create a virtual environment with uv
uv venv

# Install in editable mode with development dependencies
uv pip install -e ".[dev]"
```

## CLI Usage

The `sd-cwt` command-line tool provides utilities for creating, verifying, and selectively disclosing CWT claims.

### Using with uv run

```bash
# Show help
uv run sd-cwt --help

# Show version
uv run sd-cwt --version

# Create a new SD-CWT
uv run sd-cwt create --input claims.json --output token.cwt

# Verify an SD-CWT
uv run sd-cwt verify token.cwt

# Selectively disclose specific claims
uv run sd-cwt disclose token.cwt --claims name email --output disclosed.cwt
```

### After installation

If you've installed the package, you can use the CLI directly:

```bash
sd-cwt --help
```

## Development

### Prerequisites

- Python 3.9 or higher
- [uv](https://github.com/astral-sh/uv) package manager

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/sd-cwt.git
cd sd-cwt

# Create and activate virtual environment
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install package in editable mode with all development dependencies
uv pip install -e ".[dev,docs]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage report
uv run pytest --cov

# Run specific test file
uv run pytest tests/test_basic.py

# Run with verbose output
uv run pytest -v
```

### Code Quality

```bash
# Format code with black
uv run black src tests

# Lint with ruff
uv run ruff check src tests

# Type check with mypy
uv run mypy src

# Run all pre-commit hooks
pre-commit run --all-files
```

### Project Structure

```
sd-cwt/
├── src/
│   └── sd_cwt/          # Main package
│       ├── __init__.py   # Package initialization
│       └── cli.py        # CLI implementation
├── tests/                # Test suite
│   ├── __init__.py
│   ├── conftest.py       # Pytest configuration
│   └── test_basic.py     # Basic tests
├── docs/
│   └── specifications/   # IETF draft specifications
├── pyproject.toml        # Project configuration
├── .gitignore           # Git ignore rules
├── .pre-commit-config.yaml # Pre-commit hooks
├── LICENSE              # Apache 2.0 license
└── README.md            # This file
```

## Features (Planned)

- **SD-CWT Creation**: Generate selective disclosure CWTs with hidden claims
- **Claim Verification**: Verify the integrity and authenticity of SD-CWTs
- **Selective Disclosure**: Choose which claims to reveal during presentation
- **CBOR/COSE Support**: Full support for CBOR encoding and COSE signatures
- **Salted Hashing**: Privacy-preserving claim commitments using salted hashes
- **Holder Binding**: Optional holder binding for enhanced security

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Disclaimer

This is an experimental implementation for development and testing purposes. It should not be used in production environments without thorough security review.

## Acknowledgments

This implementation is based on the work of the IETF SPICE Working Group on the SD-CWT specification.