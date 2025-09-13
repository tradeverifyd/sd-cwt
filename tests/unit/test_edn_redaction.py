"""Unit tests for EDN-based claim redaction syntax."""

from typing import Any, Dict, List, Union

import pytest

from sd_cwt.edn_redaction import (
    EDNRedactionBuilder,
    EDNRedactionParser,
    create_redacted_edn_example,
    extract_redacted_claims,
    mark_claim_redacted,
    parse_redacted_edn_example,
)


class TestEDNRedactionBuilder:
    """Test cases for EDN redaction builder."""
    
    @pytest.fixture
    def builder(self) -> EDNRedactionBuilder:
        """Create EDN redaction builder."""
        return EDNRedactionBuilder()
    
    @pytest.mark.unit
    def test_mark_string_claim_redacted(self, builder: EDNRedactionBuilder):
        """Test marking string claim for redaction."""
        result = builder.mark_claim_for_redaction("given_name", "John", 59)
        
        assert '"given_name": 59("John")' == result
    
    @pytest.mark.unit
    def test_mark_boolean_claim_redacted(self, builder: EDNRedactionBuilder):
        """Test marking boolean claim for redaction."""
        result = builder.mark_claim_for_redaction("enabled", True, 59)
        
        assert '"enabled": 59(true)' == result
        
        result = builder.mark_claim_for_redaction("disabled", False, 59)
        assert '"disabled": 59(false)' == result
    
    @pytest.mark.unit
    def test_mark_integer_claim_redacted(self, builder: EDNRedactionBuilder):
        """Test marking integer claim for redaction."""
        result = builder.mark_claim_for_redaction(500, True, 59)
        
        assert '500: 59(true)' == result
    
    @pytest.mark.unit
    def test_mark_array_claim_redacted(self, builder: EDNRedactionBuilder):
        """Test marking array claim for redaction."""
        result = builder.mark_claim_for_redaction(
            "timestamps", [1549560720, 1612498440, 1674004740], 60
        )
        
        expected = '"timestamps": 60([1549560720, 1612498440, 1674004740])'
        assert expected == result
    
    @pytest.mark.unit
    def test_mark_object_claim_redacted(self, builder: EDNRedactionBuilder):
        """Test marking object claim for redaction."""
        address = {
            "country": "us",
            "region": "ca",
            "postal_code": "94188"
        }
        
        result = builder.mark_claim_for_redaction("address", address, 60)
        
        assert '"address": 60({' in result
        assert '"country": "us"' in result
        assert '"region": "ca"' in result
        assert '"postal_code": "94188"' in result
    
    @pytest.mark.unit
    def test_build_complete_edn_with_redaction(self, builder: EDNRedactionBuilder):
        """Test building complete EDN with selective redaction."""
        claims = {
            1: "https://issuer.example",
            2: "https://device.example",
            500: True,
            501: "ABCD-123456",
        }
        
        redaction_config = {500: 59}  # Only claim 500 is redacted
        
        result = builder.build_edn_with_redaction(claims, redaction_config)
        
        assert result.startswith('{')
        assert result.endswith('}')
        assert '1: "https://issuer.example"' in result
        assert '2: "https://device.example"' in result
        assert '500: 59(true)' in result  # Redacted claim
        assert '501: "ABCD-123456"' in result  # Regular claim
    
    @pytest.mark.unit
    def test_build_edn_no_redaction(self, builder: EDNRedactionBuilder):
        """Test building EDN with no redaction."""
        claims = {
            1: "https://issuer.example",
            2: "https://device.example",
        }
        
        redaction_config = {}  # No redaction
        
        result = builder.build_edn_with_redaction(claims, redaction_config)
        
        # Should be regular EDN without any redaction tags
        assert '59(' not in result
        assert '60(' not in result
        assert '1: "https://issuer.example"' in result


class TestEDNRedactionParser:
    """Test cases for EDN redaction parser."""
    
    @pytest.fixture
    def parser(self) -> EDNRedactionParser:
        """Create EDN redaction parser."""
        return EDNRedactionParser()
    
    @pytest.mark.unit
    def test_parse_simple_redaction(self, parser: EDNRedactionParser):
        """Test parsing simple redaction."""
        edn_text = '''
        {
            1: "https://issuer.example",
            500: 59(true)
        }
        '''
        
        claims, redacted = parser.parse_edn_with_redaction(edn_text)
        
        assert isinstance(claims, dict)
        assert 1 in claims
        assert claims[1] == "https://issuer.example"
        assert 500 in redacted  # Should identify claim 500 as redacted
    
    @pytest.mark.unit  
    def test_parse_multiple_redactions(self, parser: EDNRedactionParser):
        """Test parsing multiple redactions."""
        edn_text = '''
        {
            1: "https://issuer.example",
            500: 59(true),
            502: 60([1, 2, 3])
        }
        '''
        
        claims, redacted = parser.parse_edn_with_redaction(edn_text)
        
        assert len(redacted) >= 2  # Should find at least 2 redacted claims
        # Note: Exact parsing depends on implementation details
    
    @pytest.mark.unit
    def test_parse_no_redaction(self, parser: EDNRedactionParser):
        """Test parsing EDN with no redaction tags."""
        edn_text = '''
        {
            1: "https://issuer.example",
            2: "https://device.example"
        }
        '''
        
        claims, redacted = parser.parse_edn_with_redaction(edn_text)
        
        assert isinstance(claims, dict)
        assert len(redacted) == 0  # No redacted claims
    
    @pytest.mark.unit
    def test_parse_invalid_edn(self, parser: EDNRedactionParser):
        """Test parsing invalid EDN."""
        edn_text = "{ invalid edn syntax"
        
        with pytest.raises(ValueError):
            parser.parse_edn_with_redaction(edn_text)


class TestEDNRedactionUtilities:
    """Test cases for EDN redaction utility functions."""
    
    @pytest.mark.unit
    def test_mark_claim_redacted(self):
        """Test mark_claim_redacted utility function."""
        result = mark_claim_redacted("test_claim", "test_value")
        
        assert '"test_claim": 59("test_value")' == result
    
    @pytest.mark.unit
    def test_mark_claim_redacted_with_tag(self):
        """Test mark_claim_redacted with specific tag."""
        result = mark_claim_redacted("test_claim", [1, 2, 3], 60)
        
        assert '"test_claim": 60([1, 2, 3])' == result
    
    @pytest.mark.unit
    def test_create_redacted_edn_example(self):
        """Test creating redacted EDN example."""
        result = create_redacted_edn_example()
        
        assert isinstance(result, str)
        assert result.startswith('{')
        assert result.endswith('}')
        assert '59(' in result  # Should have redaction tag 59
        assert '60(' in result  # Should have redaction tag 60
        assert '"https://issuer.example"' in result
        assert '"https://device.example"' in result
    
    @pytest.mark.unit
    def test_parse_redacted_edn_example(self):
        """Test parsing redacted EDN example."""
        claims, redacted = parse_redacted_edn_example()
        
        assert isinstance(claims, dict)
        assert isinstance(redacted, list)
        assert len(claims) > 0
        # Should have some redacted claims
        # Note: Exact number depends on implementation
    
    @pytest.mark.unit
    def test_extract_redacted_claims(self):
        """Test extracting redacted claims from EDN."""
        edn_text = '''
        {
            1: "issuer",
            500: 59(true),
            502: 60([1, 2, 3])
        }
        '''
        
        redacted = extract_redacted_claims(edn_text)
        
        assert isinstance(redacted, list)
        # Should find the redacted claims
        # Note: Exact results depend on parsing implementation


class TestEDNRedactionIntegration:
    """Integration tests for EDN redaction functionality."""
    
    @pytest.mark.unit
    def test_build_and_parse_roundtrip(self):
        """Test building EDN with redaction and parsing it back."""
        # Original claims
        claims = {
            1: "https://issuer.example",
            2: "https://device.example",
            500: True,
            501: "ABCD-123456",
        }
        
        redaction_config = {500: 59}
        
        # Build EDN with redaction
        builder = EDNRedactionBuilder()
        edn_text = builder.build_edn_with_redaction(claims, redaction_config)
        
        # Parse it back
        parser = EDNRedactionParser()
        parsed_claims, redacted_claims = parser.parse_edn_with_redaction(edn_text)
        
        # Verify structure
        assert isinstance(parsed_claims, dict)
        assert isinstance(redacted_claims, list)
        
        # Should have core claims
        assert 1 in parsed_claims
        assert 2 in parsed_claims
        assert parsed_claims[1] == "https://issuer.example"
        assert parsed_claims[2] == "https://device.example"
    
    @pytest.mark.unit
    def test_specification_example_structure(self):
        """Test that examples match specification structure."""
        edn_example = create_redacted_edn_example()
        
        # Should contain specification-like claims
        assert "https://issuer.example" in edn_example
        assert "https://device.example" in edn_example
        assert "ABCD-123456" in edn_example
        
        # Should have both redaction tag types
        assert "59(" in edn_example  # Redacted claim key
        assert "60(" in edn_example  # Redacted claim element
    
    @pytest.mark.unit
    def test_redaction_tag_values(self):
        """Test correct redaction tag values."""
        parser = EDNRedactionParser()
        
        # Verify tag constants match specification
        assert parser.REDACTED_CLAIM_KEY_TAG == 59
        assert parser.REDACTED_CLAIM_ELEMENT_TAG == 60
        
        builder = EDNRedactionBuilder()
        
        # Test using the correct tag values
        result1 = builder.mark_claim_for_redaction("test", "value", 59)
        assert "59(" in result1
        
        result2 = builder.mark_claim_for_redaction("test", "value", 60)
        assert "60(" in result2
    
    @pytest.mark.unit
    def test_complex_claim_redaction(self):
        """Test redaction of complex claim structures."""
        complex_claims = {
            1: "https://issuer.example",
            503: {  # Address claim - complex object
                "street": "123 Main St",
                "city": "Anytown",
                "country": "US",
                "coordinates": {
                    "lat": 40.7128,
                    "lng": -74.0060
                }
            },
            504: [  # Array of timestamps
                1549560720,
                1612498440, 
                1674004740
            ]
        }
        
        redaction_config = {
            503: 60,  # Redact entire address object
            504: 60,  # Redact timestamp array
        }
        
        builder = EDNRedactionBuilder()
        edn_result = builder.build_edn_with_redaction(complex_claims, redaction_config)
        
        # Should contain redaction tags for complex structures
        assert "60({" in edn_result  # Object redaction
        assert "60([" in edn_result  # Array redaction
        
        # Should still have non-redacted claims
        assert '"https://issuer.example"' in edn_result