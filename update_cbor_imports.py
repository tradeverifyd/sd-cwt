#!/usr/bin/env python3
"""Script to update cbor2 imports to use cbor_utils wrapper."""

import os
import re
from pathlib import Path

def update_file(filepath: Path):
    """Update a single file to use cbor_utils instead of cbor2."""
    with open(filepath, 'r') as f:
        content = f.read()

    original_content = content

    # Replace import statements
    if 'import cbor2' in content and 'from . import cbor_utils' not in content:
        # Add cbor_utils import after existing imports
        import_lines = []
        other_lines = []
        in_imports = True

        for line in content.split('\n'):
            if in_imports and (line.startswith('import ') or line.startswith('from ') or line.strip() == '' or line.strip().startswith('#')):
                import_lines.append(line)
            else:
                in_imports = False
                other_lines.append(line)

        # Remove cbor2 import and add cbor_utils import
        import_lines = [line for line in import_lines if 'import cbor2' not in line]

        # Find where to insert cbor_utils import (after relative imports)
        insert_pos = len(import_lines)
        for i, line in enumerate(import_lines):
            if line.startswith('from .'):
                insert_pos = max(insert_pos, i + 1)

        import_lines.insert(insert_pos, 'from . import cbor_utils')

        content = '\n'.join(import_lines + other_lines)

    # Replace cbor2 function calls
    replacements = [
        # Basic functions
        (r'cbor2\.dumps\(', 'cbor_utils.encode('),
        (r'cbor2\.loads\(', 'cbor_utils.decode('),

        # CBOR tag handling
        (r'cbor2\.CBORTag\(([^,]+),\s*([^)]+)\)', r'cbor_utils.create_tag(\1, \2)'),
        (r'isinstance\(([^,]+),\s*cbor2\.CBORTag\)', r'cbor_utils.is_tag(\1)'),

        # CBOR simple value handling
        (r'cbor2\.CBORSimpleValue\(([^)]+)\)', r'cbor_utils.create_simple_value(\1)'),
        (r'isinstance\(([^,]+),\s*cbor2\.CBORSimpleValue\)', r'cbor_utils.is_simple_value(\1)'),

        # Exception handling
        (r'cbor2\.CBORDecodeError', 'cbor_utils.CBORDecodeError'),
    ]

    for pattern, replacement in replacements:
        content = re.sub(pattern, replacement, content)

    # Handle complex cases that need manual attention
    manual_replacements = [
        # Tag access patterns
        (r'([a-zA-Z_]\w*)\.tag\b', r'cbor_utils.get_tag_number(\1)'),
        (r'([a-zA-Z_]\w*)\.value\b', r'cbor_utils.get_tag_value(\1)'),
    ]

    # Only apply these if we detect CBORTag usage
    if 'CBORTag' in original_content:
        for pattern, replacement in manual_replacements:
            content = re.sub(pattern, replacement, content)

    if content != original_content:
        print(f"Updated {filepath}")
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    """Update all Python files in src/ and tests/ directories."""
    src_dir = Path("src/sd_cwt")
    test_dir = Path("tests")

    updated_files = 0

    # Process src files
    for py_file in src_dir.glob("*.py"):
        if py_file.name != 'cbor_utils.py':  # Skip the wrapper itself
            if update_file(py_file):
                updated_files += 1

    # Process test files
    for py_file in test_dir.rglob("*.py"):
        if update_file(py_file):
            updated_files += 1

    print(f"Updated {updated_files} files total")

if __name__ == "__main__":
    main()