#!/usr/bin/env python3
"""Script to consolidate EDN and CDDL utilities usage."""

import os
import re

def consolidate_utilities():
    """Replace direct cbor_diag and zcbor usage with utility modules."""

    # Files to update
    files_to_update = [
        "examples/sd_cwt_specification_example.py",
        "examples/validate_cbor.py",
        "tests/unit/test_cbor_edn.py",
        "tests/unit/test_issuer.py",
    ]

    for file_path in files_to_update:
        if os.path.exists(file_path):
            print(f"Updating {file_path}")
            with open(file_path, 'r') as f:
                content = f.read()

            # Replace cbor_diag imports
            content = re.sub(
                r'import cbor_diag.*\n',
                '',
                content,
                flags=re.MULTILINE
            )

            # Add edn_utils import if cbor_diag was used
            if 'cbor_diag.' in content:
                # Find the sd_cwt imports section
                if 'from sd_cwt import' in content:
                    content = re.sub(
                        r'from sd_cwt import ([^\n]*)',
                        r'from sd_cwt import \1, edn_utils',
                        content,
                        count=1
                    )
                else:
                    # Add new import
                    content = "from sd_cwt import edn_utils\n" + content

            # Replace cbor_diag usage
            content = re.sub(r'cbor_diag\.cbor2diag', 'edn_utils.cbor_to_diag', content)
            content = re.sub(r'cbor_diag\.diag2cbor', 'edn_utils.diag_to_cbor', content)

            # Replace zcbor imports if present
            content = re.sub(
                r'import zcbor.*\n',
                '',
                content,
                flags=re.MULTILINE
            )

            # Add cddl_utils import if zcbor was used
            if 'zcbor.' in content:
                if 'from sd_cwt import' in content and 'cddl_utils' not in content:
                    content = re.sub(
                        r'from sd_cwt import ([^\n]*)',
                        r'from sd_cwt import \1, cddl_utils',
                        content,
                        count=1
                    )
                elif 'from sd_cwt import' not in content:
                    content = "from sd_cwt import cddl_utils\n" + content

            # Replace zcbor usage patterns
            content = re.sub(
                r'zcbor\.DataTranslator\.from_cddl\(([^,]+),\s*[^)]*\)',
                r'cddl_utils.create_validator(\1)',
                content
            )

            with open(file_path, 'w') as f:
                f.write(content)
        else:
            print(f"File not found: {file_path}")

if __name__ == '__main__':
    consolidate_utilities()
    print("EDN and CDDL consolidation completed")