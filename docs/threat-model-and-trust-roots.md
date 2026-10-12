# Blocklog Verifier: Trust Model, Security Guarantees & Limitations

**Document Version**: 2.0  
**Status**: Normative Security Standard  
**Scope**: Standalone Verifier Engine (`blocklog-verifier`)  

---

## 1. What the Verifier Establishes vs. What It Cannot Establish

The Standalone Verifier operates entirely offline, using mathematical and cryptographic operations over provided data structures. Understanding its boundaries is critical for enterprise security teams and auditors.

### What the Verifier Cryptographically Establishes:
1. **Mathematical Integrity**: Proves that the receipt payload byte-for-byte matches the computed canonical NFC-normalized SHA-256 hash.
2. **Signature Provenance**: Proves that the private key corresponding to the verified public key signed the canonical receipt envelope.
3. **Cryptographic Inclusion**: Proves that a specific receipt leaf hash is contained at a specific leaf index within an RFC 6962 Merkle tree committed under root $R_N$.
4. **Append-Only Extension (When Earlier State Provided)**: Proves that tree state $N$ strictly extends earlier committed tree state $M$ without altering or reordering earlier leaves.
5. **Witness Corroboration**: Proves that one or more independent witness private keys signed an acknowledgement binding the log identifier, tree size, and root hash.
6. **Counterparty Origin Authentication**: Proves that an external counterparty's private key signed an assertion binding the execution ID, receipt ID, and request fingerprint.

### What the Verifier CANNOT Establish in Isolation:
1. **Real-World Truth**: A valid digital signature confirms that a specific key made a statement; it cannot prove that the statement is true or that external physical machinery/bank ledgers executed correctly.
2. **Global Anti-Equivocation (Without Witness State or Checkpoint History)**: An offline verifier verifying a single checkpoint in isolation cannot detect if a rogue operator presented a different checkpoint to another auditor (split-view attack). Detecting equivocation requires comparing against previously stored checkpoints or querying independent witnesses who persistently track monotonic state.
3. **Completeness of Omitted Actions**: The verifier validates evidence for actions presented to it. It cannot detect actions the operator chose not to log unless an external audit trail or continuous sequence stream is reconciled.
4. **Trust Root Authenticity**: If an adversary alters the local `trust_roots.json` file, the verifier will validate signatures against the adversary's keys. Trust roots must be distributed over authenticated, out-of-band channels.

---

## 2. Threat Analysis & Verification Guarantees

| Attack / Adversary Action | Detection Mechanism | Failure Behavior |
|---|---|---|
| **Payload Mutation** | Recomputing the canonical NFC-normalized JSON hash does not match `canonical_serialization_hash` or signed bytes. | Fails `canonical_hash` or `signature` check. `verified = false`. |
| **Signature Forgery** | Attacker signs receipt with an unconfigured or unauthorized key. | Key resolution fails or signature check fails. `verified = false`. |
| **Key Compromise & Revocation** | Operator or adversary signs with a key marked `status: "revoked"` in trust roots. | Verifier detects revoked status. Fails `trust_root_status` check. `verified = false`. |
| **Tree Size Rollback** | Operator presents an older tree snapshot $N_{smaller} < N_{current}$ to hide recent events. | Independent witnesses compare incoming size with local SQLite state. Rejects with signed `TREE_ROLLBACK`. |
| **Split-View / Forking** | Operator issues two conflicting roots for the same tree size $N$. | Witnesses detect conflicting roots for identical sizes. Rejects with signed `FORK_DETECTED`. |
| **History Deletion / Mutation** | Operator modifies an earlier record and signs a larger tree. | RFC 6962 consistency proof fails to mathematically link root $R_{old}$ with $R_{new}$. `verified = false`. |
| **Counterparty Context Replay** | Attacker attaches a valid counterparty signature from a different transaction. | Verifier checks binding against `execution_id`, `receipt_id`, and `request_fingerprint`. Fails binding check. |

---

## 3. Trust Root Lifecycle & Management

Blocklog defines explicit lifecycle semantics for verification keys:

```
┌──────────┐        Key Rotation        ┌──────────────┐       Key Compromise       ┌───────────┐
│  active  │ ─────────────────────────► │  deprecated  │ ─────────────────────────► │  revoked  │
└──────────┘                            └──────────────┘                            └───────────┘
```

- **`active`**: Authorized for current signing and verification.
- **`deprecated`**: Key has been rotated. Prohibited for new receipt issuance, but valid for historical receipt verification.
- **`revoked`**: Key has been compromised or retired under incident conditions. **The verifier immediately halts verification with `KEY_REVOKED`**.

### Trust Root JSON Schema

```json
[
  {
    "key_id": "blocklog:execution-key:prod-2026",
    "public_key": "111e9a8683267c1456d4ddcdf665e25a3cef54819b95cfc603a1759ecdc40fc0",
    "status": "active",
    "algorithm": "ed25519",
    "valid_from": "2026-01-01T00:00:00.000000Z",
    "valid_until": "2027-01-01T00:00:00.000000Z"
  }
]
```

---

## 4. Witness Independence Assumptions

Independent witnessing provides defence-in-depth against a malicious or compromised log operator:

1. **Operational Separation**: Witnesses must run on physically or administratively isolated infrastructure from the primary Blocklog API. Running a witness on the same database or credentials as Blocklog provides zero independent assurance.
2. **State Durability**: Witnesses must persist their observed state (`log_id`, `tree_size`, `root_hash`) to durable write-ahead storage (such as `SqliteWitnessStorage`) before acknowledging a checkpoint to survive reboots without state loss.
3. **Quorum Policies**: Relying parties should configure minimum witness quorum requirements (e.g. at least 2 distinct external witnesses must acknowledge a checkpoint).

---

## 5. Outcome Confidence Taxonomy

The verifier classifies outcome claims into an evidence hierarchy:

| Level | Source | Confidence | Description |
|---|---|---|---|
| **Level 4** | `counterparty_attested` | `MAXIMAL` | Validated by an Ed25519 signature from an explicitly pinned counterparty key matching transaction context. |
| **Level 3** | `adapter_verified` | `HIGH` | Response captured directly by a credential-custody adapter during controlled dispatch. |
| **Level 2** | `recorded_downstream` | `MEDIUM` | Downstream reference recorded, but without counterparty digital signature. |
| **Level 1** | `agent_reported` | `LOW` | Self-reported claim by the autonomous agent without independent corroboration. Emits auditor warning. |

---

## 6. Behavior Under Missing, Malformed, or Stale Evidence

- **Missing Signature**: Fails verification with `Missing cryptographic signature` unless explicitly bypassed with `--no-signature`.
- **Missing Merkle Proof**: If `--require-merkle` is set, fails verification. If not required, emits a warning.
- **Missing Witness ACKs**: The verifier verifies the checkpoint signature and marks transparency status as `CHECKPOINTED` rather than `WITNESSED`.
- **Missing Counterparty Attestation**: Outcome assurance is evaluated from the receipt's native source (e.g. `adapter_verified` or `agent_reported`).
