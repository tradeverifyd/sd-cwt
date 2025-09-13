#!/usr/bin/env python3
"""Fix test imports to use correct cbor_utils import."""

import os
import re

def fix_test_imports():
    """Fix all test files to use correct cbor_utils import."""
    test_files = [
        'tests/unit/test_validation.py',
        'tests/unit/test_cddl_validation.py',
        'tests/integration/test_end_to_end.py',
        'tests/unit/test_issuer.py',
        'tests/unit/test_disclosure.py',
        'tests/unit/test_cbor_edn.py',
        'tests/unit/test_thumbprint.py',
        'tests/unit/test_cwt.py',
        'tests/test_cose_sign1.py',
        'tests/test_cose_keys.py',
        'tests/test_edge_cases.py',
        'tests/test_redaction.py',
        'tests/test_holder_binding.py',
        'tests/test_mandatory_to_disclose_claims.py',
        'tests/test_verifier_cddl_validation.py'
    ]

    for file_path in test_files:
        if os.path.exists(file_path):
            print(f"Fixing {file_path}")
            with open(file_path, 'r') as f:
                content = f.read()

            # Replace the import statement
            content = re.sub(
                r'^from \. import cbor_utils$',
                'from sd_cwt import cbor_utils',
                content,
                flags=re.MULTILINE
            )

            with open(file_path, 'w') as f:
                f.write(content)
        else:
            print(f"File not found: {file_path}")

if __name__ == '__main__':
    fix_test_imports()
    print("Test import fixes completed")