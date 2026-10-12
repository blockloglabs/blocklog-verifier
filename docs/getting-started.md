# Getting Started with Blocklog Verifier

**Target Audience**: Auditors, Regulators, Compliance Officers, Developers  
**Prerequisites**: Python 3.9+  

---

## 1. What is the Blocklog Verifier?

Autonomous AI agents, financial systems, and industrial robotics make consequential decisions that require independent proof. When an organization runs Blocklog to audit autonomous actions, it generates an **Execution Receipt**.

The **Blocklog Standalone Verifier** (`blocklog-verifier`) is an open-source, air-gapped cryptographic engine that proves:
1. **Who authorized the action?** (Validated via Blocklog's digital signature and policy commitments)
2. **Was the receipt altered?** (Validated via NFC-normalized canonical SHA-256 hash)
3. **Is the receipt anchored in a public log?** (Validated via RFC 6962 Merkle inclusion proofs)
4. **Did the operator fork or rollback history?** (Validated via independent witness acknowledgements)
5. **Did the action happen in the real world?** (Validated via counterparty digital attestations)

All of this happens **without connecting to Blocklog's servers or databases**.

---

## 2. Installation

### Quick Install via Git

```bash
git clone https://github.com/blocklog/blocklog.git
cd blocklog
pip install ./verifier
```

Verify your installation:

```bash
blocklog-verify --help
# Or:
python -m verifier --help
```

---

## 3. Your First Verification (30 Seconds)

Navigate to the repository root and test against the bundled working example:

```bash
python -m verifier verifier/examples/witnessed_receipt.json \
  --trust-root-file verifier/examples/trust_roots.json \
  --witness-roots verifier/examples/witness_roots.json \
  --counterparty-roots verifier/examples/counterparty_roots.json \
  --verbose
```

### Expected Output:

```
============================================================
BLOCKLOG INDEPENDENT RECEIPT VERIFICATION
============================================================

✓ VERIFICATION PASSED: Cryptographic integrity confirmed
ℹ Receipt ID: rcpt_demo_2026_001
ℹ Verified At: 2026-10-10T12:00:00.000000Z
ℹ Transparency Status: WITNESSED (Witness ACKs verified: 1)
ℹ Claimed Status: succeeded (Source: counterparty_attested)
ℹ Real-World Verified: True (Confidence: MAXIMAL)

Verification Checks:
✓   [schema_version] Receipt version '1.0' recognized
✓   [required_fields] All required envelope fields present
✓   [execution_commitment_syntax] Execution commitment format valid
✓   [outcome_commitment_syntax] Outcome commitment format valid
✓   [canonical_hash] Canonical serialization hash matches payload
✓   [merkle_proof] Merkle inclusion proof verified against root 89d02b9c18274b41...
✓   [signature] Ed25519 signature valid using key 'blocklog:execution-key:prod-2026'
✓   [checkpoint_version] Checkpoint protocol version 'checkpoint/1.0' recognized
✓   [checkpoint_structure] Valid checkpoint structure for log 'blocklog:global:transparency-v1' (tree_size=4)
✓   [checkpoint_signature] Checkpoint signature valid under key 'blocklog:execution-key:prod-2026'
✓   [counterparty_attestation_0] Valid attestation from Stripe US Inc. (succeeded)
✓   [outcome_assurance] Outcome backed by independent evidence (source=counterparty_attested, confidence=MAXIMAL)

============================================================
```

---

## 4. Next Steps

- Explore the [CLI Guide](cli-guide.md) for automation and JSON output.
- Learn how to integrate the [Python SDK](python-sdk.md) into your auditing pipelines.
- Understand the [Threat Model and Trust Roots](threat-model-and-trust-roots.md).
