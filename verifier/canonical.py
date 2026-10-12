"""
Standalone Canonical Serialization

Implements normative canonical JSON encoding according to
docs/protocol/execution-receipt-spec.md with zero external dependencies.
"""
import hashlib
import json
import unicodedata
from typing import Any


def nfc_normalize(obj: Any) -> Any:
    """Recursively apply Unicode NFC normalization to all string values."""
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        return {nfc_normalize(k): nfc_normalize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [nfc_normalize(item) for item in obj]
    return obj


def canonical_encode(obj: Any) -> bytes:
    """
    Produce canonical UTF-8 bytes for a JSON-serializable structure.
    
    Rules:
    - Recursively NFC-normalized strings
    - Sorted keys by UTF-8 byte order
    - Compact separators (',', ':')
    - Explicit null preserved
    - Empty collections preserved
    """
    normalized = nfc_normalize(obj)
    canonical_str = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return canonical_str.encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    """Compute SHA-256 hex string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
