"""Validate claim locations, not just presence of an expected disclosed value."""

import pytest

from sd_cwt import cbor_utils as cbor
from sd_cwt.redaction import hash_disclosure, reconstruct_claims

R = cbor.create_simple_value(59)


def disclosure(value, key=None, salt=b"s" * 16):
    return cbor.encode([salt, value] + ([] if key is None else [key]))


@pytest.mark.parametrize("reverse", [False, True])
def test_nested_parent_array_and_same_names_in_different_maps(reverse):
    child = disclosure("inner", "name")
    parent = disclosure({"visible": True, R: [hash_disclosure(child)]}, "profile", b"p" * 16)
    item = disclosure({"name": "array"}, salt=b"a" * 16)
    payload = {
        "name": "outer",
        500: True,
        R: [hash_disclosure(parent)],
        "items": ["public", cbor.create_tag(60, hash_disclosure(item))],
    }
    ds = [child, parent, item]
    assert reconstruct_claims(payload, ds[::-1] if reverse else ds) == {
        "name": "outer",
        500: True,
        "profile": {"visible": True, "name": "inner"},
        "items": ["public", {"name": "array"}],
    }
    assert reconstruct_claims(payload, []) == {"name": "outer", 500: True, "items": ["public"]}
    assert reconstruct_claims(payload, [parent])["profile"] == {"visible": True}


def test_no_flattening_and_no_redaction_metadata_in_draft():
    from pathlib import Path

    token = cbor.get_tag_value(
        cbor.decode((Path(__file__).parent / "fixtures/draft-09/issuer_cwt.cbor").read_bytes())
    )
    claims = reconstruct_claims(cbor.decode(token[2]), token[1][17])
    assert claims[500] is True
    assert claims[502] == [1549560720, 1612560720, 1674004740]
    assert claims[503] == {"country": "us", "region": "ca", "postal_code": "94188"}
    assert "region" not in claims and R not in claims and R not in claims[503]


def test_reject_duplicate_map_key():
    d = disclosure("hidden", "name")
    with pytest.raises(ValueError, match="duplicate"):
        reconstruct_claims({"name": "visible", R: [hash_disclosure(d)]}, [d])


@pytest.mark.parametrize("duplicate", [False, True])
def test_reject_orphan_or_repeated_disclosure(duplicate):
    d = disclosure("hidden", "name")
    with pytest.raises(ValueError):
        reconstruct_claims(
            {R: [hash_disclosure(d)]} if duplicate else {}, [d, d] if duplicate else [d]
        )


def test_reject_child_without_disclosed_parent():
    child = disclosure("hidden", "name")
    parent = disclosure({R: [hash_disclosure(child)]}, "profile", b"p" * 16)
    with pytest.raises(ValueError, match="no Redacted"):
        reconstruct_claims({R: [hash_disclosure(parent)]}, [child])


@pytest.mark.parametrize("map_entry", [False, True])
def test_reject_disclosure_at_wrong_kind_of_location(map_entry):
    d = disclosure("value", "key") if map_entry else disclosure("value")
    payload = (
        {"items": [cbor.create_tag(60, hash_disclosure(d))]}
        if map_entry
        else {R: [hash_disclosure(d)]}
    )
    with pytest.raises(ValueError, match="shape mismatch"):
        reconstruct_claims(payload, [d])


def test_reject_reuse_of_one_hash_in_two_locations():
    d = disclosure("value", "key")
    payload = {"a": {R: [hash_disclosure(d)]}, "b": {R: [hash_disclosure(d)]}}
    with pytest.raises(ValueError, match="more than once"):
        reconstruct_claims(payload, [d])


@pytest.mark.parametrize("bad", [[b"salt", 1, 2, 3], ["not bytes", "value"], {}])
def test_reject_malformed_disclosure(bad):
    with pytest.raises(ValueError, match="invalid salted"):
        reconstruct_claims({}, [cbor.encode(bad)])


@pytest.mark.parametrize("hashes", ["not an array", [123]])
def test_reject_invalid_hash_locations(hashes):
    with pytest.raises(ValueError):
        reconstruct_claims({R: hashes}, [])


def test_preserve_unrelated_tags():
    value = cbor.create_tag(999, {"value": 7})
    assert reconstruct_claims({"tagged": value}, []) == {"tagged": value}


def test_reject_array_placeholder_outside_array():
    with pytest.raises(ValueError, match="outside an array"):
        reconstruct_claims({"bad": cbor.create_tag(60, b"h" * 32)}, [])


def test_bound_nested_disclosure_recursion():
    ds = []
    value = "leaf"
    for _ in range(17):
        d = disclosure(value, "child")
        ds.append(d)
        value = {R: [hash_disclosure(d)]}
    with pytest.raises(ValueError, match="maximum depth"):
        reconstruct_claims(value, ds)
