"""Command-line interface for sd-cwt."""

import argparse
import sys
from collections.abc import Sequence
from typing import Optional

from . import __version__


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="sd-cwt",
        description="SPICE SD-CWT toolkit for selective disclosure CWTs",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Create subcommand
    create_parser = subparsers.add_parser("create", help="Create a new SD-CWT")
    create_parser.add_argument("--input", "-i", help="Input file (JSON format)")
    create_parser.add_argument("--output", "-o", help="Output file")

    # Verify subcommand
    verify_parser = subparsers.add_parser("verify", help="Verify an SD-CWT")
    verify_parser.add_argument("input", help="SD-CWT file to verify")

    # Disclose subcommand
    disclose_parser = subparsers.add_parser("disclose", help="Create selective disclosure")
    disclose_parser.add_argument("input", help="SD-CWT file")
    disclose_parser.add_argument("--claims", "-c", nargs="+", help="Claims to disclose")
    disclose_parser.add_argument("--output", "-o", help="Output file")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    # Placeholder for future command implementations
    print(f"Command '{args.command}' is not yet implemented")
    print("This is a placeholder for the sd-cwt CLI")

    return 0


if __name__ == "__main__":
    sys.exit(main())
