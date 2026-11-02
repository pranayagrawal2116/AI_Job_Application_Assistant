"""RFC 8785 JSON Canonicalization Scheme (JCS) encoder and packet hasher.

Provides deterministic canonical serialization and hashing compliant with RFC 8785:
- UTF-16 code unit property key sorting
- IEEE 754 / ECMAScript 6 number serialization (-0 -> 0, integer floats formatted as ints)
- Rejection of NaN and Infinity
- Strict minimal JSON encoding without extraneous whitespace
"""

import hashlib
import json
import math
from typing import Any, Dict, Union

try:
    import rfc8785

    def canonical_json_bytes(data: Any) -> bytes:
        """Serializes data into RFC 8785 canonical UTF-8 bytes using verified JCS implementation."""
        if data is None:
            return b"null"
        return rfc8785.dumps(data)

except ImportError:  # pragma: no cover - fallback for environments without rfc8785 package
    def _utf16_sort_key(s: str) -> bytes:
        return s.encode("utf-16-be")

    def _serialize_number(n: Union[int, float]) -> str:
        if isinstance(n, bool):
            return "true" if n else "false"
        if isinstance(n, int):
            return str(n)
        if isinstance(n, float):
            if math.isnan(n) or math.isinf(n):
                raise ValueError(f"RFC 8785 rejects non-finite float: {n}")
            if n == 0.0:
                return "0"
            if n.is_integer() and abs(n) < 1e21:
                return str(int(n))
            s = f"{n:.16g}"
            return s.replace("e+", "e").replace("E+", "e").replace("E", "e")
        raise TypeError(f"Unsupported number type: {type(n)}")

    def _serialize_string(s: str) -> str:
        out = ['"']
        for char in s:
            cp = ord(char)
            if cp == 0x22:
                out.append('\\"')
            elif cp == 0x5C:
                out.append('\\\\')
            elif cp == 0x08:
                out.append('\\b')
            elif cp == 0x0C:
                out.append('\\f')
            elif cp == 0x0A:
                out.append('\\n')
            elif cp == 0x0D:
                out.append('\\r')
            elif cp == 0x09:
                out.append('\\t')
            elif cp < 0x20:
                out.append(f"\\u{cp:04x}")
            else:
                out.append(char)
        out.append('"')
        return "".join(out)

    def _serialize_val(val: Any) -> str:
        if val is None:
            return "null"
        if isinstance(val, bool):
            return "true" if val else "false"
        if isinstance(val, (int, float)):
            return _serialize_number(val)
        if isinstance(val, str):
            return _serialize_string(val)
        if isinstance(val, (list, tuple)):
            return "[" + ",".join(_serialize_val(item) for item in val) + "]"
        if isinstance(val, dict):
            sorted_keys = sorted(val.keys(), key=_utf16_sort_key)
            items = [_serialize_string(k) + ":" + _serialize_val(val[k]) for k in sorted_keys]
            return "{" + ",".join(items) + "}"
        raise TypeError(f"RFC 8785 cannot serialize type: {type(val)}")

    def canonical_json_bytes(data: Any) -> bytes:
        return _serialize_val(data).encode("utf-8")


def canonical_json_hash(data: Any) -> str:
    """Computes SHA-256 digest of RFC 8785 canonical serialized bytes."""
    return hashlib.sha256(canonical_json_bytes(data)).hexdigest()
