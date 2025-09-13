#!/usr/bin/env python3
"""Script to remove unused cbor2 imports."""

import os
import re
from pathlib import Path

def clean_cbor2_import(filepath: Path):
    """Remove cbor2 import if it's no longer used."""
    with open(filepath, 'r') as f:
        content = f.read()

    original_content = content

    # Remove standalone cbor2 import lines
    patterns_to_remove = [
        r'^import cbor2\s*$',  # Standalone import cbor2
        r'^import cbor2\s*#.*$',  # import cbor2 with comment
    ]

    lines = content.split('\n')
    cleaned_lines = []

    for line in lines:
        should_remove = False
        for pattern in patterns_to_remove:
            if re.match(pattern, line.strip()):
                should_remove = True
                break

        if not should_remove:
            cleaned_lines.append(line)

    content = '\n'.join(cleaned_lines)

    if content != original_content:
        print(f"Cleaned cbor2 import from {filepath}")
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    """Clean cbor2 imports from all files except cbor_utils.py."""
    src_dir = Path("src/sd_cwt")
    test_dir = Path("tests")

    updated_files = 0

    # Process src files
    for py_file in src_dir.glob("*.py"):
        if py_file.name != 'cbor_utils.py':  # Keep the cbor2 import in the wrapper
            if clean_cbor2_import(py_file):
                updated_files += 1

    # Process test files
    for py_file in test_dir.rglob("*.py"):
        if clean_cbor2_import(py_file):
            updated_files += 1

    print(f"Cleaned {updated_files} files total")

if __name__ == "__main__":
    main()