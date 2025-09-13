from . import cbor_utils
"""EDN-based claim redaction syntax for SD-CWT.

This module provides utilities for marking claims for redaction using
CBOR Extended Diagnostic Notation (EDN) with redaction tags as specified
in draft-ietf-spice-sd-cwt.
"""

import re
from typing import Any, Union

from . import edn_utils


class EDNRedactionParser:
    """Parser for EDN with redaction tags."""

    # Redaction tags from specification
    REDACTED_CLAIM_KEY_TAG = 58  # TBD3 - tag for to-be-redacted keys
    REDACTED_CLAIM_ELEMENT_TAG = 58  # TBD3 - tag for to-be-redacted array elements

    def __init__(self) -> None:
        """Initialize EDN redaction parser."""
        self.redacted_claims: list[Union[str, int]] = []

    def parse_edn_with_redaction(
        self, edn_text: str
    ) -> tuple[dict[Any, Any], list[Union[str, int]]]:
        """Parse EDN text and extract redaction information.

        Args:
            edn_text: EDN text with redaction tags

        Returns:
            Tuple of (parsed_claims, redacted_claim_names)
        """
        self.redacted_claims = []

        # Find redaction tags in the EDN text
        redaction_patterns = [
            rf"{self.REDACTED_CLAIM_KEY_TAG}\([^)]+\)",  # 59(value)
            rf"{self.REDACTED_CLAIM_ELEMENT_TAG}\([^)]+\)",  # 60(value)
        ]

        processed_edn = edn_text

        # Look for redaction patterns and collect claim names
        for pattern in redaction_patterns:
            matches = re.finditer(pattern, edn_text)
            for match in matches:
                # Extract the claim name associated with this redaction
                self._extract_claim_name_from_context(edn_text, match.start())

        # For now, create a simplified version without tags for parsing
        # TODO: Implement proper CBOR tag parsing
        clean_edn = self._remove_redaction_tags(processed_edn)

        try:
            cbor_data = edn_utils.diag_to_cbor(clean_edn)
            claims = cbor_utils.decode(cbor_data)
        except Exception as e:
            raise ValueError(f"Failed to parse EDN: {e}") from e

        return claims, self.redacted_claims

    def _extract_claim_name_from_context(self, edn_text: str, tag_pos: int) -> None:
        """Extract claim name from the context around a redaction tag."""
        # Find the line containing the tag
        lines = edn_text[:tag_pos].split("\n")
        current_line = lines[-1] if lines else ""

        # Look for the claim name pattern: "claim_name": redaction_tag
        # This is a simplified approach - in practice, we'd need proper parsing
        if ":" in current_line:
            parts = current_line.split(":")
            if len(parts) >= 2:
                claim_name = parts[0].strip().strip('"').strip("'")
                if claim_name.isdigit():
                    # Integer claim label
                    self.redacted_claims.append(int(claim_name))
                elif claim_name and not claim_name.startswith("{"):
                    # String claim name
                    self.redacted_claims.append(claim_name)

    def _remove_redaction_tags(self, edn_text: str) -> str:
        """Remove redaction tags from EDN text for parsing."""
        # Remove redaction tag syntax like 59(value) and 60(value)
        # Replace with just the value inside parentheses

        # Handle 59(value) -> value
        edn_text = re.sub(rf"{self.REDACTED_CLAIM_KEY_TAG}\(([^)]+)\)", r"\1", edn_text)

        # Handle 60(value) -> value
        edn_text = re.sub(rf"{self.REDACTED_CLAIM_ELEMENT_TAG}\(([^)]+)\)", r"\1", edn_text)

        return edn_text


class EDNRedactionBuilder:
    """Builder for creating EDN with redaction tags."""

    def __init__(self) -> None:
        """Initialize EDN redaction builder."""
        pass

    def mark_claim_for_redaction(
        self, claim_name: Union[str, int], claim_value: Any, tag: int = 59
    ) -> str:
        """Mark a claim for redaction using EDN syntax.

        Args:
            claim_name: Name or integer label of the claim
            claim_value: Value of the claim
            tag: CBOR tag to use (59 or 60)

        Returns:
            EDN representation with redaction tag
        """
        # Convert claim value to EDN representation
        if isinstance(claim_value, str):
            value_edn = f'"{claim_value}"'
        elif isinstance(claim_value, bool):
            value_edn = "true" if claim_value else "false"
        elif isinstance(claim_value, (int, float)):
            value_edn = str(claim_value)
        elif isinstance(claim_value, bytes):
            value_edn = f"h'{claim_value.hex()}'"
        elif isinstance(claim_value, list):
            # Convert list to EDN array
            elements = []
            for item in claim_value:
                if isinstance(item, str):
                    elements.append(f'"{item}"')
                elif isinstance(item, (int, float)):
                    elements.append(str(item))
                else:
                    elements.append(str(item))
            value_edn = f"[{', '.join(elements)}]"
        elif isinstance(claim_value, dict):
            # Convert dict to EDN object
            pairs = []
            for k, v in claim_value.items():
                key_edn = f'"{k}"' if isinstance(k, str) else str(k)

                if isinstance(v, str):
                    val_edn = f'"{v}"'
                elif isinstance(v, (int, float)):
                    val_edn = str(v)
                else:
                    val_edn = str(v)

                pairs.append(f"{key_edn}: {val_edn}")
            value_edn = f"{{{', '.join(pairs)}}}"
        else:
            value_edn = str(claim_value)

        # Create claim entry with redaction tag
        claim_key = f'"{claim_name}"' if isinstance(claim_name, str) else str(claim_name)

        return f"{claim_key}: {tag}({value_edn})"

    def build_edn_with_redaction(
        self, claims: dict[Any, Any], redaction_config: dict[Any, int]
    ) -> str:
        """Build complete EDN with selective redaction.

        Args:
            claims: Dictionary of all claims
            redaction_config: Dictionary mapping claim names to redaction tags

        Returns:
            Complete EDN text with redaction tags
        """
        edn_lines = ["{"]

        for claim_name, claim_value in claims.items():
            if claim_name in redaction_config:
                # This claim should be redacted
                tag = redaction_config[claim_name]
                line = "    " + self.mark_claim_for_redaction(claim_name, claim_value, tag)
            else:
                # Regular claim without redaction
                key_edn = f'"{claim_name}"' if isinstance(claim_name, str) else str(claim_name)

                if isinstance(claim_value, str):
                    val_edn = f'"{claim_value}"'
                elif isinstance(claim_value, bool):
                    val_edn = "true" if claim_value else "false"
                elif isinstance(claim_value, (int, float)):
                    val_edn = str(claim_value)
                elif isinstance(claim_value, bytes):
                    val_edn = f"h'{claim_value.hex()}'"
                else:
                    # For complex types, convert to CBOR then back to EDN
                    try:
                        cbor_data = cbor_utils.encode(claim_value)
                        val_edn = edn_utils.cbor_to_diag(cbor_data)
                    except Exception:
                        val_edn = str(claim_value)

                line = f"    {key_edn}: {val_edn}"

            edn_lines.append(line + ",")

        # Remove trailing comma from last line
        if len(edn_lines) > 1 and edn_lines[-1].endswith(","):
            edn_lines[-1] = edn_lines[-1][:-1]

        edn_lines.append("}")

        return "\n".join(edn_lines)


def create_redacted_edn_example() -> str:
    """Create an example of EDN with redaction tags matching the specification.

    Returns:
        EDN text with redaction tags
    """
    claims = {
        1: "https://issuer.example",
        2: "https://device.example",
        6: 1725244200,
        500: True,  # device_enabled - to be redacted
        501: "ABCD-123456",  # device_id - visible
        502: [1549560720, 1612498440, 1674004740],  # timestamps - to be redacted
        503: {"country": "us", "region": "ca", "postal_code": "94188"},  # address - visible
    }

    # Mark claims 500 and 502 for redaction
    redaction_config = {
        500: 59,  # Redacted claim key tag
        502: 60,  # Redacted claim element tag
    }

    builder = EDNRedactionBuilder()
    return builder.build_edn_with_redaction(claims, redaction_config)


def parse_redacted_edn_example() -> tuple[dict[Any, Any], list[Union[str, int]]]:
    """Parse an example of redacted EDN.

    Returns:
        Tuple of (claims, redacted_claim_names)
    """
    edn_text = create_redacted_edn_example()

    parser = EDNRedactionParser()
    return parser.parse_edn_with_redaction(edn_text)


# Convenience functions for common operations


def mark_claim_redacted(claim_name: Union[str, int], claim_value: Any, tag: int = 59) -> str:
    """Mark a single claim for redaction.

    Args:
        claim_name: Name or label of the claim
        claim_value: Value of the claim
        tag: CBOR tag to use (59 or 60)

    Returns:
        EDN representation with redaction tag
    """
    builder = EDNRedactionBuilder()
    return builder.mark_claim_for_redaction(claim_name, claim_value, tag)


def extract_redacted_claims(edn_text: str) -> list[Union[str, int]]:
    """Extract list of redacted claim names from EDN text.

    Args:
        edn_text: EDN text with redaction tags

    Returns:
        List of claim names that are marked for redaction
    """
    parser = EDNRedactionParser()
    _, redacted_claims = parser.parse_edn_with_redaction(edn_text)
    return redacted_claims
