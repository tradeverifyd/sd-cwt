"""Basic tests for sd-cwt package."""

from sd_cwt import __version__, main


def test_version():
    """Test that version is set correctly."""
    assert __version__ == "0.1.0"


def test_main(capsys):
    """Test main function output."""
    main()
    captured = capsys.readouterr()
    assert "Hello from sd-cwt!" in captured.out
