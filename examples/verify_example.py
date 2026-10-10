#!/usr/bin/env python3
"""
Blocklog Verifier - Complete Working Python API Example.

Demonstrates:
1. Loading an execution receipt from disk.
2. Configuring trust roots for Blocklog, independent witnesses, and counterparties.
3. Performing complete offline cryptographic verification.
4. Inspecting machine-readable outcome and transparency assessments.
"""
import json
import sys
from pathlib import Path

# Ensure verifier package is importable when run directly
repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from verifier import (
    StandaloneReceiptVerifier,
    TrustRoot,
    canonical_encode,
    sha256_hex,
    rfc6962_leaf_hash,
    rfc6962_tree_hash,
    rfc6962_inclusion_proof,
    IndependentWitness,
    CounterpartySigner,
)


def main():
    print("=" * 70)
    print("BLOCKLOG VERIFIER - PYTHON API DEMO")
    print("=" * 70)

    # ── 1. Setup Sample Cryptographic Keys ───────────────────────────────────
    bl_key = ed25519.Ed25519PrivateKey.generate()
    bl_pub_hex = bl_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    wit_key = ed25519.Ed25519PrivateKey.generate()
    wit_priv_hex = wit_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    wit_pub_hex = wit_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    cp_key = ed25519.Ed25519PrivateKey.generate()
    cp_priv_hex = cp_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    cp_pub_hex = cp_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    # ── 2. Construct Sample Execution Receipt ─────────────────────────────────
    execution_id = "exec_demo_2026_001"
    receipt_id = "rcpt_demo_2026_001"
    fingerprint = sha256_hex("action:financial.transfer:target:acc_99:amount:100000")

    receipt = {
        "version": "1.0",
        "receipt_id": receipt_id,
        "execution_id": execution_id,
        "realm": {
            "company_id": "acme-corp",
            "environment": "production"
        },
        "policy": {
            "policy_id": "pol_high_value_transfers",
            "policy_version": 2,
            "policy_hash": sha256_hex("policy_v2_rules"),
            "decision": "APPROVED",
            "risk_score": 12,
            "risk_level": "LOW"
        },
        "execution": {
            "processor": "financial.stripe",
            "action_type": "payment.transfer",
            "started_at": "2026-10-10T12:00:00.000000Z",
            "completed_at": "2026-10-10T12:00:01.000000Z"
        },
        "commitments": {
            "execution_commitment": sha256_hex("exec_intent_commitment"),
            "outcome_commitment": sha256_hex("outcome_evidence_commitment")
        },
        "outcome": {
            "status": "succeeded",
            "source": "adapter_verified"
        },
        "integrity": {},
        "signing": {
            "signer_key_id": "blocklog:execution-key:prod-2026",
            "algorithm": "ed25519",
            "signed_at": "2026-10-10T12:00:01.000000Z"
        }
    }

    # ── 3. Commit to Transparency Tree & Generate RFC 6962 Proof ──────────────
    leaf_0 = rfc6962_leaf_hash("receipt_leaf_commitment")
    other_leaves = [rfc6962_leaf_hash(f"leaf_{i}") for i in range(1, 4)]
    all_leaves = [leaf_0] + other_leaves

    tree_root = rfc6962_tree_hash(all_leaves)
    merkle_proof = rfc6962_inclusion_proof(0, all_leaves)

    receipt["integrity"] = {
        "merkle_root": tree_root.hex(),
        "merkle_proof": {
            "leaf_hash": leaf_0.hex(),
            "sibling_hashes": merkle_proof
        }
    }

    # Compute canonical hash and sign receipt
    receipt_copy = dict(receipt)
    receipt_copy["signing"] = dict(receipt["signing"])
    receipt_copy["signing"].pop("signature", None)
    can_hash = sha256_hex(canonical_encode(receipt_copy))
    receipt["integrity"]["canonical_serialization_hash"] = can_hash

    to_sign = dict(receipt)
    to_sign["signing"] = dict(receipt["signing"])
    to_sign["signing"].pop("signature", None)
    receipt["signing"]["signature"] = bl_key.sign(canonical_encode(to_sign)).hex()

    # ── 4. Attach Checkpoint & Independent Witness ACK ────────────────────────
    checkpoint = {
        "protocol_version": "checkpoint/1.0",
        "checkpoint_id": "cp_2026_q4_001",
        "log_id": "blocklog:global:transparency-v1",
        "tree_size": 4,
        "root_hash": tree_root.hex(),
        "previous_root_hash": None,
        "timestamp": "2026-10-10T12:00:02.000000Z",
        "signing": {
            "signer_key_id": "blocklog:execution-key:prod-2026",
            "algorithm": "ed25519"
        }
    }
    cp_bytes = canonical_encode({
        "protocol_version": checkpoint["protocol_version"],
        "log_id": checkpoint["log_id"],
        "tree_size": checkpoint["tree_size"],
        "root_hash": checkpoint["root_hash"].lower(),
        "timestamp": checkpoint["timestamp"],
        "checkpoint_id": checkpoint["checkpoint_id"],
        "previous_root_hash": checkpoint["previous_root_hash"],
        "signer_key_id": checkpoint["signing"]["signer_key_id"],
        "algorithm": checkpoint["signing"]["algorithm"],
    })
    checkpoint["signing"]["signature"] = bl_key.sign(cp_bytes).hex()
    receipt["transparency_checkpoint"] = checkpoint

    witness = IndependentWitness(
        witness_id="audit.watchdog-global.org",
        witness_key_id="witness:key:watchdog-2026",
        witness_private_key_hex=wit_priv_hex,
        log_trust_roots={"blocklog:execution-key:prod-2026": bl_pub_hex},
    )
    ack = witness.observe_checkpoint(checkpoint)
    receipt["witness_attestations"] = [ack.to_dict()]

    # ── 5. Attach Counterparty Attestation ────────────────────────────────────
    cp_signer = CounterpartySigner(
        organization_id="org_stripe_us",
        organization_name="Stripe US Inc.",
        role="payment_processor",
        key_id="stripe:key:2026",
        private_key_hex=cp_priv_hex,
    )
    attestation = cp_signer.sign_attestation(
        attestation_id="att_stripe_001",
        execution_id=execution_id,
        receipt_id=receipt_id,
        request_fingerprint=fingerprint,
        downstream_reference="ch_3N1234567890ABCDEF",
        outcome_status="succeeded",
        operation_type="payment.transfer",
        amount_settled_minor=100000,
        currency="USD",
    )
    receipt["counterparty_attestations"] = [attestation.to_dict()]

    # Save to example files
    examples_dir = Path(__file__).parent
    with open(examples_dir / "witnessed_receipt.json", "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2)

    with open(examples_dir / "trust_roots.json", "w", encoding="utf-8") as f:
        json.dump([
            {
                "key_id": "blocklog:execution-key:prod-2026",
                "public_key": bl_pub_hex,
                "status": "active",
                "algorithm": "ed25519"
            }
        ], f, indent=2)

    with open(examples_dir / "witness_roots.json", "w", encoding="utf-8") as f:
        json.dump({"witness:key:watchdog-2026": wit_pub_hex}, f, indent=2)

    with open(examples_dir / "counterparty_roots.json", "w", encoding="utf-8") as f:
        json.dump({"stripe:key:2026": cp_pub_hex}, f, indent=2)

    # ── 6. Verify Receipt with Standalone Verifier ────────────────────────────
    verifier = StandaloneReceiptVerifier(
        trust_roots={"blocklog:execution-key:prod-2026": TrustRoot("blocklog:execution-key:prod-2026", bl_pub_hex)},
        witness_trust_roots={"witness:key:watchdog-2026": wit_pub_hex},
        counterparty_trust_roots={"stripe:key:2026": cp_pub_hex},
    )

    result = verifier.verify(receipt)

    print(f"\nResult: {'VERIFIED' if result.verified else 'FAILED'}")
    print(f"Receipt ID: {result.receipt_id}")
    print(f"Transparency Assessment: {result.transparency_assessment}")
    print(f"Outcome Assessment: {result.outcome_assessment}")
    print("\nChecks:")
    for chk in result.checks:
        status_sym = "✓" if chk.passed else "✗"
        print(f"  {status_sym} [{chk.name}] {chk.detail}")

    print("\nSaved examples to verifier/examples/")
    print("=" * 70)


if __name__ == "__main__":
    main()
