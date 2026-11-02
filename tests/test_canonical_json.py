"""Tests for RFC 8785 JSON Canonicalization Scheme (JCS) encoder."""

import pytest
from src.utils.canonical_json import canonical_json_bytes, canonical_json_hash


def test_rfc8785_key_sorting_utf16_code_units():
    """Verify that object keys are sorted by UTF-16 code units (RFC 8785 Section 3.2.3)."""
    # Astral symbol U+10000 has UTF-16 surrogate pair 0xD800, 0xDC00.
    # BMP symbol U+E000 has code unit 0xE000.
    # In UTF-16 code units: 0xD800 < 0xE000, so '\U00010000' MUST come before '\uE000'.
    data = {
        "\uE000": "bmp_high",
        "\U00010000": "astral",
        "a": 1,
        "z": 26,
    }
    encoded = canonical_json_bytes(data)
    # Keys in expected order: 'a', '\U00010000', '\uE000', 'z'
    # Check that astral symbol appears before BMP high
    astral_pos = encoded.find(b"\xf0\x90\x80\x80")
    bmp_pos = encoded.find(b"\xee\x80\x80")
    assert astral_pos != -1 and bmp_pos != -1
    assert astral_pos < bmp_pos


def test_rfc8785_number_formatting():
    """Verify IEEE 754 / ECMAScript 6 number formatting rules."""
    # Negative zero must normalize to 0
    assert canonical_json_bytes(-0.0) == b"0"
    assert canonical_json_bytes(0.0) == b"0"

    # Float integers must format without decimal or exponent
    assert canonical_json_bytes(1.0) == b"1"
    assert canonical_json_bytes(42.0) == b"42"
    assert canonical_json_bytes(-100.0) == b"-100"

    # Decimal floats
    assert canonical_json_bytes(3.14159) == b"3.14159"
    assert canonical_json_bytes(0.0001) == b"0.0001"


def test_rfc8785_rejection_of_nan_and_infinity():
    """Verify that NaN and Infinity are strictly rejected."""
    with pytest.raises(Exception):
        canonical_json_bytes(float("nan"))

    with pytest.raises(Exception):
        canonical_json_bytes(float("inf"))

    with pytest.raises(Exception):
        canonical_json_bytes(float("-inf"))


def test_rfc8785_object_key_order_invariance():
    """Different dictionary key insertion orders must yield identical canonical bytes and hashes."""
    dict_1 = {"z": 100, "a": 1, "m": {"sub_z": 2, "sub_a": 1}}
    dict_2 = {"a": 1, "m": {"sub_a": 1, "sub_z": 2}, "z": 100}

    assert canonical_json_bytes(dict_1) == canonical_json_bytes(dict_2)
    assert canonical_json_hash(dict_1) == canonical_json_hash(dict_2)


def test_rfc8785_string_escaping_rules():
    """Verify that only required characters are escaped (quotes, backslash, control chars)."""
    # Solidus / must NOT be escaped
    assert canonical_json_bytes("http://example.com/api/v1") == b'"http://example.com/api/v1"'

    # Quotes and backslash must be escaped
    assert canonical_json_bytes('hello "world" \\ test') == b'"hello \\"world\\" \\\\ test"'

    # Control characters
    assert canonical_json_bytes("line1\nline2\ttab") == b'"line1\\nline2\\ttab"'


def test_rfc8785_nested_structures_and_arrays():
    """Verify deeply nested structures and arrays retain exact determinism."""
    data = {
        "user_id": 42,
        "active": True,
        "metadata": None,
        "tags": ["ml", "ai", "python"],
        "nested": {
            "scores": [1.0, 2.5, -0.0],
            "details": {"approved": False},
        },
    }
    encoded = canonical_json_bytes(data)
    expected = b'{"active":true,"metadata":null,"nested":{"details":{"approved":false},"scores":[1,2.5,0]},"tags":["ml","ai","python"],"user_id":42}'
    assert encoded == expected
