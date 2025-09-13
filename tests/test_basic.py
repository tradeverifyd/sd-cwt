"""Basic tests for sd-cwt package."""

from sd_cwt import __version__


def test_version():
    """Test that version is set correctly."""
    assert __version__ == "0.1.0"
