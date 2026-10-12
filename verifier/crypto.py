"""
Cryptographic verification primitives for standalone verifier.
Uses reviewed `cryptography` library with Ed25519.
"""
import base64
from typing import Optional
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


def decode_bytes(val: str) -> bytes:
    """Decode raw bytes from hex or base64/base64url."""
    clean = val.strip()
    if clean.lower().startswith("0x"):
        clean = clean[2:]

    # Check hex first (64 hex chars = 32 bytes)
    if len(clean) in (64, 128) and all(c in "0123456789abcdefABCDEF" for c in clean):
        try:
            return bytes.fromhex(clean)
        except ValueError:
            pass

    # Try base64url or standard base64
    padding = "=" * (-len(clean) % 4)
    padded = clean + padding
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        try:
            return base64.b64decode(padded)
        except Exception as exc:
            raise ValueError(f"Unable to decode cryptographic bytes from string: {val[:16]}...") from exc


def verify_ed25519_signature(
    public_key_raw: str | bytes,
    signature_raw: str | bytes,
    message: bytes,
) -> bool:
    """
    Verify Ed25519 signature over canonical message bytes.
    Returns True if valid, False if signature does not match.
    Raises ValueError on malformed key or signature.
    """
    pub_bytes = decode_bytes(public_key_raw) if isinstance(public_key_raw, str) else public_key_raw
    sig_bytes = decode_bytes(signature_raw) if isinstance(signature_raw, str) else signature_raw

    if len(pub_bytes) != 32:
        raise ValueError(f"Invalid Ed25519 public key length: {len(pub_bytes)} bytes (expected 32)")
    if len(sig_bytes) != 64:
        raise ValueError(f"Invalid Ed25519 signature length: {len(sig_bytes)} bytes (expected 64)")

    public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    try:
        public_key.verify(sig_bytes, message)
        return True
    except InvalidSignature:
        return False
