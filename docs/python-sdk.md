# Blocklog Verifier Python SDK Reference

The `verifier` package provides programmatic access to Blocklog's cryptographic verification engine.

---

## 1. Quick Example

```python
from verifier import verify_receipt_file, TrustRoot

trust_roots = {
    "blocklog:key:2026": TrustRoot(
        key_id="blocklog:key:2026",
        public_key="111e9a8683267c1456d4ddcdf665e25a3cef54819b95cfc603a1759ecdc40fc0",
        status="active"
    )
}

result = verify_receipt_file("receipt.json", trust_roots=trust_roots)
print("Verified:", result.verified)
```

---

## 2. API Reference

### `StandaloneReceiptVerifier`

```python
class StandaloneReceiptVerifier:
    def __init__(
        self,
        trust_roots: Optional[Dict[str, TrustRoot]] = None,
        default_public_key: Optional[str] = None,
        witness_trust_roots: Optional[Dict[str, str]] = None,
        counterparty_trust_roots: Optional[Dict[str, str]] = None,
    ): ...

    def verify(
        self,
        receipt: Dict[str, Any],
        public_key_override: Optional[str] = None,
        require_signature: bool = True,
        require_merkle: bool = False,
    ) -> VerificationResult: ...

    def verify_checkpoint(
        self,
        checkpoint: Dict[str, Any],
        previous_checkpoint: Optional[Dict[str, Any]] = None,
        consistency_proof: Optional[List[str]] = None,
    ) -> VerificationResult: ...

    def verify_witness_acknowledgement(
        self,
        ack: Dict[str, Any] | WitnessAcknowledgement,
        checkpoint: Dict[str, Any],
    ) -> VerificationResult: ...
```

### `VerificationResult`

```python
@dataclass
class VerificationResult:
    verified: bool
    receipt_id: Optional[str]
    verified_at: str
    signature_verified: bool = False
    cryptographically_verified: bool = False
    structural_valid: bool = True
    checks: List[VerificationCheck] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    outcome_assessment: Optional[Dict[str, Any]] = None
    transparency_assessment: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]: ...
```

---

## 3. Cryptographic Primitives

```python
from verifier import (
    canonical_encode,
    sha256_hex,
    rfc6962_leaf_hash,
    rfc6962_tree_hash,
    rfc6962_inclusion_proof,
    rfc6962_verify_inclusion,
    rfc6962_consistency_proof,
    rfc6962_verify_consistency,
    verify_ed25519_signature,
)
```

- `canonical_encode(obj)`: Encodes arbitrary JSON-serializable Python data into canonical UTF-8 bytes (NFC normalized, lexicographically sorted keys, compact separators).
- `rfc6962_consistency_proof(m, leaves)`: Generates an append-only consistency proof that tree of size $N = \text{len}(leaves)$ strictly extends tree of size $m$.
- `rfc6962_verify_consistency(m, n, root_m, root_n, proof)`: Verifies consistency proof without access to original leaves.
