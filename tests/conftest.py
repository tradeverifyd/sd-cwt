"""Pytest configuration and shared fixtures for SD-CWT tests."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Generator

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryptionAvailable,
    PrivateFormat,
    PublicFormat,
)


@pytest.fixture(scope="session")
def test_data_dir() -> Path:
    """Return the path to test data directory."""
    return Path(__file__).parent / "data"


@pytest.fixture(scope="session")
def ec_keypair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate an EC P-256 keypair for testing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def sample_claims() -> Dict[str, Any]:
    """Provide sample JWT/CWT claims for testing."""
    now = datetime.now(timezone.utc)
    return {
        "iss": "https://issuer.example.com",
        "sub": "user123",
        "aud": "https://audience.example.com",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "nbf": int(now.timestamp()),
        "iat": int(now.timestamp()),
        "jti": "unique-token-id-123",
        "given_name": "John",
        "family_name": "Doe",
        "email": "john.doe@example.com",
        "phone_number": "+1234567890",
        "address": {
            "street": "123 Main St",
            "city": "Anytown",
            "state": "CA",
            "postal_code": "12345",
            "country": "US",
        },
        "birthdate": "1990-01-01",
        "is_verified": True,
        "roles": ["user", "admin"],
    }


@pytest.fixture
def minimal_claims() -> Dict[str, Any]:
    """Provide minimal JWT/CWT claims for testing."""
    now = datetime.now(timezone.utc)
    return {
        "iss": "https://issuer.example.com",
        "sub": "user123",
        "iat": int(now.timestamp()),
    }


@pytest.fixture
def selective_disclosure_claims() -> Dict[str, Any]:
    """Claims marked for selective disclosure."""
    return {
        "given_name": "John",
        "family_name": "Doe",
        "email": "john.doe@example.com",
        "phone_number": "+1234567890",
        "birthdate": "1990-01-01",
    }


@pytest.fixture
def cbor_encoder():
    """Provide a configured CBOR encoder."""
    return cbor2.CBOREncoder()


@pytest.fixture
def cbor_decoder():
    """Provide a configured CBOR decoder."""
    return cbor2.CBORDecoder()


@pytest.fixture
def sample_salts() -> Dict[str, bytes]:
    """Provide sample salts for testing selective disclosure."""
    return {
        "given_name": b"salt1" * 8,  # 40 bytes
        "family_name": b"salt2" * 8,
        "email": b"salt3" * 8,
        "phone_number": b"salt4" * 8,
        "birthdate": b"salt5" * 8,
    }


@pytest.fixture
def hash_function():
    """Provide the hash function for SD calculations."""
    return hashes.SHA256()


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables for each test."""
    original_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def temp_keys_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for key storage."""
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    return keys_dir


@pytest.fixture
def mock_cwt_token() -> bytes:
    """Provide a mock CWT token for testing."""
    # This is a simplified mock - real implementation would use proper COSE
    mock_payload = {
        "iss": "test-issuer",
        "sub": "test-subject",
        "iat": 1234567890,
        "_sd": ["hash1", "hash2", "hash3"],  # Selective disclosure hashes
        "_sd_alg": "sha-256",
    }
    return cbor2.dumps(mock_payload)


@pytest.fixture
def disclosure_array() -> list:
    """Provide sample disclosure array for testing."""
    return [
        ["salt1", "given_name", "John"],
        ["salt2", "family_name", "Doe"],
        ["salt3", "email", "john.doe@example.com"],
    ]


class TestDataManager:
    """Helper class for managing test data files."""

    def __init__(self, base_path: Path):
        self.base_path = base_path

    def read_json(self, filename: str) -> Dict[str, Any]:
        """Read JSON test data file."""
        with open(self.base_path / filename, "r") as f:
            return json.load(f)

    def read_cbor(self, filename: str) -> Any:
        """Read CBOR test data file."""
        with open(self.base_path / filename, "rb") as f:
            return cbor2.load(f)

    def write_json(self, filename: str, data: Dict[str, Any]) -> None:
        """Write JSON test data file."""
        with open(self.base_path / filename, "w") as f:
            json.dump(data, f, indent=2)

    def write_cbor(self, filename: str, data: Any) -> None:
        """Write CBOR test data file."""
        with open(self.base_path / filename, "wb") as f:
            cbor2.dump(data, f)


@pytest.fixture
def test_data_manager(test_data_dir: Path) -> TestDataManager:
    """Provide test data manager instance."""
    return TestDataManager(test_data_dir)


@pytest.fixture
def performance_timer():
    """Fixture for timing test performance."""
    import time

    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None

        def start(self):
            self.start_time = time.perf_counter()

        def stop(self):
            self.end_time = time.perf_counter()

        @property
        def elapsed(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None

    return Timer()


def pytest_configure(config):
    """Configure pytest with custom settings."""
    config.addinivalue_line(
        "markers", "requires_network: mark test as requiring network access"
    )
    config.addinivalue_line(
        "markers", "requires_crypto: mark test as requiring cryptographic operations"
    )