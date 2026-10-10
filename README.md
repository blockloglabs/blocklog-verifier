# Blocklog Standalone Verifier (`blocklog-verifier`)

[![CI](https://github.com/blockloglabs/blocklog-verifier/actions/workflows/verifier-ci.yml/badge.svg)](https://github.com/blockloglabs/blocklog-verifier/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The **Blocklog Standalone Verifier** (`blocklog-verifier`) is an independent, air-gapped cryptographic library and command-line utility for validating **Blocklog Execution Receipts**, **RFC 6962 Transparency Checkpoints**, **Independent Witness Acknowledgements**, and **Downstream Counterparty Attestations**.

It executes **offline without runtime API calls or database connections**, enabling external auditors, regulators, counterparties, and clients to verify execution records using locally supplied trust roots.

---

## Technical Guarantees

| Verification Check | What It Establishes | What It Does NOT Establish |
|---|---|---|
| **Ed25519 Signature** | Proves the holder of the corresponding private key signed the exact canonical bytes of the receipt. | Does not independently prove that the real-world event occurred or that claims made by the signer are truthful. |
| **Canonical SHA-256 Hash** | Proves the receipt payload has not been modified since hash generation, using deterministic Unicode NFC-normalized canonical JSON. | Does not validate whether the signed commitments accurately reflect physical sensor or financial ledger states. |
| **Merkle Inclusion Proof** | Proves a specific receipt leaf hash is committed within a Merkle tree of size $N$ at a specific root hash $R_N$. | Does not prove the log has not forked or omitted other events unless cross-checked against signed checkpoints. |
| **RFC 6962 Consistency Proof** | Proves that a tree of size $N$ is a strictly append-only continuation of an earlier committed tree of size $M$ ($M \le N$). | Does not prevent a malicious operator from publishing two different append-only histories to separate parties (equivocation). |
| **Witness Acknowledgements** | Proves that an independent witness observed the signed checkpoint, verified tree monotonicity, and recorded its state. | Depends on witness operational separation and uncompromised witness signing keys. |
| **Counterparty Attestation** | Proves that an external entity (e.g., payment gateway, industrial PLC) signed an assertion binding execution IDs and fingerprints. | Does not replace independent audit of the external counterparty's internal systems. |

---

## Installation

The verifier has zero runtime dependencies beyond Python standard libraries and the audited `cryptography` package (`>=41.0.0`).

### Option A: From PyPI (Recommended when published)

```bash
pip install blocklog-verifier
```

### Option B: From Git Repository

```bash
# Clone the repository
git clone https://github.com/blockloglabs/blocklog-verifier.git
cd blocklog

# Install the verifier package
pip install ./verifier
```

### Option C: Standalone Package Directory

If using the `verifier/` directory as a standalone project:

```bash
cd verifier
pip install .
```

### Development Installation

To install with test dependencies (`pytest`):

```bash
pip install -e "./verifier[dev]"

# Run standalone verifier test suite
pytest verifier/tests/ -v
```

---

## Command-Line Usage

The package installs the `blocklog-verify` console entry point. Alternatively, invoke the module directly with `python -m verifier`.

### Basic Verification

Verify an execution receipt using an explicit public key:

```bash
blocklog-verify receipt.json --public-key <ED25519_PUBLIC_KEY_HEX>
```

### Multi-Organization Verification with Trust Roots

Verify a receipt containing Merkle proofs, transparency checkpoints, witness acknowledgements, and counterparty attestations:

```bash
blocklog-verify verifier/examples/witnessed_receipt.json \
  --trust-root-file verifier/examples/trust_roots.json \
  --witness-roots verifier/examples/witness_roots.json \
  --counterparty-roots verifier/examples/counterparty_roots.json \
  --verbose
```

### Machine-Readable JSON Output

Incorporate verification directly into automated audit jobs or CI/CD pipelines:

```bash
blocklog-verify receipt.json \
  --trust-root-file trust_roots.json \
  --json-output > verification_result.json
```

### CLI Flags Reference

| Flag | Description | Security Note |
|---|---|---|
| `receipt_file` | Path to the receipt JSON file to verify. | *Required positional argument* |
| `-k, --public-key` | Raw Ed25519 public key (hex or base64). | Overrides trust-root file lookups. |
| `--key-id` | Key ID for trust-root lookup. | Optional hint. |
| `--trust-root-file` | JSON file containing trusted Blocklog signing keys. | Essential for key rotation/revocation handling. |
| `--witness-roots` | JSON file mapping `witness_key_id -> ed25519_pubkey_hex`. | Required to validate witness signatures. |
| `--counterparty-roots` | JSON file mapping `counterparty_key_id -> ed25519_pubkey_hex`. | Required to validate counterparty assertions. |
| `--require-merkle` | Fail verification if Merkle inclusion proof is absent. | Enforces batch or transparency log commitment. |
| `--no-signature` | Structural and commitment validation only. | **CAUTION: Bypasses cryptographic signature check.** |
| `-j, --json-output` | Output raw structured JSON verification object. | Useful for automated policy engines. |
| `-v, --verbose` | Print formatted human-readable terminal output. | Displays all granular check statuses. |

---

## Understanding `--no-signature` (Structural Validation Only)

> [!WARNING]
> The `--no-signature` flag bypasses all digital signature checks. It validates envelope schemas, commitment formats, and canonical serialization hashes, but **does NOT establish receipt authenticity, non-repudiation, or origin**.
> 
> Never use `--no-signature` to make authorization, financial, legal, or security decisions.

When `--no-signature` is supplied, the verifier explicitly reports:
- Machine-readable JSON output sets `signature_verified: false` and `cryptographically_verified: false`.
- The `checks` array includes an explicit `signature_verification: SKIPPED` check.
- Human-readable output displays `STRUCTURAL VALIDATION PASSED (Cryptographic signature was NOT verified)`.

---

## Python API Usage

```python
from verifier import StandaloneReceiptVerifier, TrustRoot, verify_receipt_file

# 1. Configure trusted public keys
verifier = StandaloneReceiptVerifier(
    trust_roots={
        "blocklog:execution-key:prod-2026": TrustRoot(
            key_id="blocklog:execution-key:prod-2026",
            public_key="111e9a8683267c1456d4ddcdf665e25a3cef54819b95cfc603a1759ecdc40fc0",
            status="active",
        )
    },
    witness_trust_roots={
        "witness:key:watchdog-2026": "d519fc28a4962caf8567c0cd7f47d034c0edd900292de17842800a68fc0b9462"
    },
    counterparty_trust_roots={
        "stripe:key:2026": "0a2be8677f9fc1b9d51773fe1b4ad7fdffa644b5d7839963362b11f8a0757d0a"
    }
)

# 2. Perform verification
result = verifier.verify(receipt_dict)

# 3. Inspect results
if result.verified and result.cryptographically_verified:
    print(f"Cryptographic verification confirmed for {result.receipt_id}")
    print(f"Transparency Status: {result.transparency_assessment['status']}")
    print(f"Outcome Source: {result.outcome_assessment['source_type']}")
    print(f"Confidence Level: {result.outcome_assessment['confidence']}")
else:
    print("Verification failed or incomplete:", result.errors)
```

---

## Outcome Confidence Classification

Blocklog execution receipts categorize outcome claims by evidence origin:

| Source Identifier | Confidence Rating | Operational Meaning |
|---|---|---|
| `counterparty_attested` | `MAXIMAL` | The outcome is supported by an independently signed assertion from an external counterparty whose public key is pinned in counterparty trust roots. |
| `adapter_verified` | `HIGH` | The direct downstream response was captured and committed by a credential-custody adapter. |
| `recorded_downstream` | `MEDIUM` | Downstream transaction reference or hash is committed, but lacks counterparty signature. |
| `agent_reported` | `LOW` | The autonomous agent self-asserted success without external corroboration. The verifier flags this with an explicit auditor warning. |

---

## Trust Model and Limitations

### 1. Root Keys and Key Distribution
- The verifier relies on out-of-band provisioning of trust roots (`trust_roots.json`).
- If an adversary substitutes the public keys in your trust roots, they can forge receipts that pass verification.
- Always obtain trust roots over authenticated, tamper-resistant channels (such as Blocklog's `/.well-known/blocklog-keys.json` served over verified HTTPS, or pinned DNSSEC/PGP releases).

### 2. Key Lifecycle (Active, Deprecated, Revoked)
- `active`: Key is authorized for signing current receipts and checkpoints.
- `deprecated`: Key is retired from signing new records, but valid for verifying historical records signed before the deprecation timestamp.
- `revoked`: Key was compromised. **The verifier immediately rejects any receipt or checkpoint signed by a revoked key.**

### 3. Equivocation and Monotonicity Assumptions
- An offline verifier inspecting a single checkpoint in isolation can prove the checkpoint is signed by an authorized key, but **cannot detect if the operator presented a conflicting checkpoint to another party (split-view attack)**.
- Anti-equivocation and rollback detection require comparing checkpoints against a previously trusted checkpoint or querying independent witnesses who persistently maintain monotonic state.

### 4. Counterparty Verification Limits
- A valid counterparty signature confirms that the configured organization's key signed the statement. It does not replace internal operational auditing of that counterparty's ledger or sensors.

### 5. Missing Evidence Handling
- If a receipt references a Merkle proof but omits sibling hashes, verification fails.
- If witness acknowledgements are absent, the verifier marks transparency status as `CHECKPOINTED` (or `UNCHECKPOINTED`) rather than `WITNESSED`.

---

## Repository Structure

```
verifier/
├── __init__.py           # Library public API exports
├── __main__.py           # python -m verifier entry point
├── cli.py                # Standalone CLI implementation
├── core.py               # Core receipt & checkpoint verification engine
├── canonical.py          # Deterministic NFC-normalized canonical JSON encoder
├── crypto.py             # Ed25519 signature verification primitives
├── merkle.py             # RFC 6962 Merkle tree, inclusion & consistency proofs
├── witness.py            # Independent witness state & anti-equivocation logic
├── attestation.py        # Counterparty attestation signer & validator
├── pyproject.toml        # Package manifest and build metadata
├── LICENSE               # Apache License 2.0
├── NOTICE                # Apache 2.0 attribution notices
├── examples/             # Self-contained fixture files & API demo script
│   ├── witnessed_receipt.json
│   ├── trust_roots.json
│   ├── witness_roots.json
│   ├── counterparty_roots.json
│   └── verify_example.py
└── tests/                # Standalone unit & regression test suite
    ├── conftest.py
    └── test_standalone.py
```

---

## License and Attribution

Licensed under the Apache License, Version 2.0 (the "License"). You may obtain a copy of the License at [LICENSE](LICENSE) or at:

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

See [NOTICE](NOTICE) for required attribution notices.
