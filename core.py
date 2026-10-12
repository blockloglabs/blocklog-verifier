"""
Core standalone receipt & transparency verifier implementation.

Operates with zero backend dependencies, providing complete offline cryptographic
verification of receipts, Merkle inclusion proofs, transparency checkpoints,
Merkle consistency proofs, witness acknowledgements, and counterparty attestations.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from verifier.canonical import canonical_encode, sha256_hex
from verifier.crypto import decode_bytes, verify_ed25519_signature
from verifier.merkle import (
    rfc6962_verify_consistency,
    rfc6962_verify_inclusion,
)
from verifier.witness import (
    WitnessAcknowledgement,
    canonicalize_checkpoint_for_verification,
)
from verifier.attestation import (
    CounterpartyAttestation,
    verify_counterparty_attestation,
)


@dataclass
class VerificationCheck:
    name: str
    passed: bool
    detail: str


@dataclass
class TrustRoot:
    key_id: str
    public_key: str
    status: str = "active"  # "active", "deprecated", "revoked"
    algorithm: str = "ed25519"


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

    def add_check(self, name: str, passed: bool, detail: str) -> None:
        self.checks.append(VerificationCheck(name=name, passed=passed, detail=detail))
        if not passed:
            self.verified = False
            self.errors.append(f"{name}: {detail}")
            if name in (
                "schema_version",
                "required_fields",
                "commitments_format",
                "execution_commitment_syntax",
                "execution_commitment_length",
                "outcome_commitment_syntax",
                "canonical_hash",
            ):
                self.structural_valid = False

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class StandaloneReceiptVerifier:
    """
    Independent cryptographic verifier for Blocklog receipts, checkpoints,
    witness acknowledgements, and external counterparties.
    Runs completely offline with no network or database connectivity required.
    """

    def __init__(
        self,
        trust_roots: Optional[Dict[str, TrustRoot]] = None,
        default_public_key: Optional[str] = None,
        witness_trust_roots: Optional[Dict[str, str]] = None,  # witness_key_id -> ed25519 pubkey hex
        counterparty_trust_roots: Optional[Dict[str, str]] = None,  # counterparty_key_id -> ed25519 pubkey hex
    ):
        self.trust_roots: Dict[str, TrustRoot] = trust_roots or {}
        self.default_public_key = default_public_key
        self.witness_trust_roots: Dict[str, str] = witness_trust_roots or {}
        self.counterparty_trust_roots: Dict[str, str] = counterparty_trust_roots or {}

    def add_trust_root(self, root: TrustRoot) -> None:
        self.trust_roots[root.key_id] = root

    def add_witness_trust_root(self, key_id: str, public_key_hex: str) -> None:
        self.witness_trust_roots[key_id] = public_key_hex

    def add_counterparty_trust_root(self, key_id: str, public_key_hex: str) -> None:
        self.counterparty_trust_roots[key_id] = public_key_hex

    # ── Checkpoint Verification ──────────────────────────────────────────────

    def verify_checkpoint(
        self,
        checkpoint: Dict[str, Any],
        previous_checkpoint: Optional[Dict[str, Any]] = None,
        consistency_proof: Optional[List[str]] = None,
    ) -> VerificationResult:
        """
        Verify a transparency checkpoint, its signature, and consistency with prior state.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        res = VerificationResult(
            verified=True,
            receipt_id=None,
            verified_at=now_iso,
        )

        # 1. Version Check
        ver = checkpoint.get("protocol_version")
        if ver != "checkpoint/1.0":
            res.add_check("checkpoint_version", False, f"Unsupported checkpoint protocol: {ver}")
            return res
        res.add_check("checkpoint_version", True, "Checkpoint protocol version 'checkpoint/1.0' recognized")

        # 2. Required fields
        tree_size = checkpoint.get("tree_size")
        root_hash = checkpoint.get("root_hash", "").lower()
        log_id = checkpoint.get("log_id")

        if tree_size is None or not root_hash or not log_id:
            res.add_check("checkpoint_structure", False, "Missing log_id, tree_size, or root_hash")
            return res
        res.add_check("checkpoint_structure", True, f"Valid checkpoint structure for log '{log_id}' (tree_size={tree_size})")

        # 3. Signature & Key check
        signing = checkpoint.get("signing", {})
        signer_key_id = signing.get("signer_key_id")
        sig_raw = signing.get("signature")

        if not signer_key_id or not sig_raw:
            res.add_check("checkpoint_signature", False, "Missing signer_key_id or signature")
            return res

        pubkey = self.default_public_key
        key_status = "active"
        if signer_key_id in self.trust_roots:
            tr = self.trust_roots[signer_key_id]
            pubkey = tr.public_key
            key_status = tr.status

        if key_status == "revoked":
            res.add_check("checkpoint_key_status", False, f"Signing key '{signer_key_id}' is REVOKED")
            return res

        if not pubkey:
            res.add_check("checkpoint_signature", False, f"Untrusted signer key '{signer_key_id}'")
            return res

        msg = canonicalize_checkpoint_for_verification(checkpoint)
        if not verify_ed25519_signature(pubkey, sig_raw, msg):
            res.add_check("checkpoint_signature", False, "Checkpoint signature verification failed")
            return res
        res.add_check("checkpoint_signature", True, f"Checkpoint signature valid under key '{signer_key_id}'")

        # 4. Consistency against previous checkpoint if provided
        if previous_checkpoint:
            prev_size = previous_checkpoint.get("tree_size", 0)
            prev_root = previous_checkpoint.get("root_hash", "").lower()

            if tree_size < prev_size:
                res.add_check("tree_monotonicity", False, f"Tree size rollback: {tree_size} < previous {prev_size}")
                return res

            if tree_size == prev_size:
                if root_hash != prev_root:
                    res.add_check("anti_fork", False, f"Fork detected: identical size {tree_size} has conflicting roots")
                    return res
                res.add_check("anti_fork", True, "Checkpoint matches previous root identically")
            else:
                # tree_size > prev_size: verify consistency proof
                if not consistency_proof:
                    res.add_check("consistency_proof", False, "Missing required consistency proof for growing tree")
                    return res

                valid_cons = rfc6962_verify_consistency(prev_size, tree_size, prev_root, root_hash, consistency_proof)
                if not valid_cons:
                    res.add_check("consistency_proof", False, f"RFC 6962 consistency proof failed between size {prev_size} and {tree_size}")
                    return res
                res.add_check("consistency_proof", True, f"Consistency verified from size {prev_size} to {tree_size}")
        else:
            res.add_warning("No previous trusted checkpoint provided: verified signature only, not history continuity")

        return res

    # ── Witness Acknowledgement Verification ─────────────────────────────────

    def verify_witness_acknowledgement(
        self,
        ack: Dict[str, Any] | WitnessAcknowledgement,
        checkpoint: Dict[str, Any],
    ) -> VerificationResult:
        now_iso = datetime.now(timezone.utc).isoformat()
        res = VerificationResult(verified=True, receipt_id=None, verified_at=now_iso)

        if isinstance(ack, dict):
            ack_obj = WitnessAcknowledgement(**ack)
        else:
            ack_obj = ack

        # Check binding to checkpoint
        if ack_obj.log_id != checkpoint.get("log_id"):
            res.add_check("witness_log_binding", False, f"Log ID mismatch: {ack_obj.log_id} != {checkpoint.get('log_id')}")
        if ack_obj.tree_size != checkpoint.get("tree_size"):
            res.add_check("witness_size_binding", False, f"Tree size mismatch: {ack_obj.tree_size} != {checkpoint.get('tree_size')}")
        if ack_obj.root_hash.lower() != checkpoint.get("root_hash", "").lower():
            res.add_check("witness_root_binding", False, f"Root hash mismatch: {ack_obj.root_hash} != {checkpoint.get('root_hash')}")

        # Check witness signature
        w_pubkey = self.witness_trust_roots.get(ack_obj.witness_key_id)
        if not w_pubkey:
            res.add_check("witness_trust_root", False, f"Witness key '{ack_obj.witness_key_id}' not in trusted witness roots")
            return res

        if not verify_ed25519_signature(w_pubkey, ack_obj.signature, ack_obj.canonical_bytes()):
            res.add_check("witness_signature", False, "Witness acknowledgement signature verification failed")
            return res

        res.add_check("witness_signature", True, f"Witness acknowledgement valid from witness '{ack_obj.witness_id}'")
        return res

    # ── Receipt Verification (Complete Multi-Tier) ───────────────────────────

    def verify(
        self,
        receipt: Dict[str, Any],
        public_key_override: Optional[str] = None,
        require_signature: bool = True,
        require_merkle: bool = False,
        allowed_witness_ids: Optional[list] = None,
    ) -> VerificationResult:
        receipt_id = receipt.get("receipt_id")
        now_iso = datetime.now(timezone.utc).isoformat()
        result = VerificationResult(
            verified=True,
            receipt_id=receipt_id,
            verified_at=now_iso,
        )

        # ── 1. Schema Version Check ──────────────────────────────────────────
        version = receipt.get("version") or receipt.get("schema_version")
        if not version:
            result.add_check("schema_version", False, "Missing version field")
        elif version not in ("1.0", "execution/1.0", "blocklog-verification-v1"):
            result.add_check("schema_version", False, f"Unsupported receipt version: {version}")
        else:
            result.add_check("schema_version", True, f"Receipt version '{version}' recognized")

        # ── 2. Required Envelope Fields ──────────────────────────────────────
        required_fields = ["execution_id", "policy", "execution", "commitments"]
        missing = [f for f in required_fields if f not in receipt]
        if missing:
            result.add_check("required_fields", False, f"Missing required fields: {', '.join(missing)}")
        else:
            result.add_check("required_fields", True, "All required envelope fields present")

        # ── 3. Commitments Verification ──────────────────────────────────────
        commitments = receipt.get("commitments", {})
        if not isinstance(commitments, dict):
            result.add_check("commitments_format", False, "Commitments block must be a JSON object")
        else:
            if "execution_commitment" in commitments and commitments["execution_commitment"]:
                exec_comm = commitments["execution_commitment"]
                if len(exec_comm) != 64:
                    result.add_check("execution_commitment_length", False, f"Invalid hash length: {len(exec_comm)}")
                else:
                    result.add_check("execution_commitment_syntax", True, "Execution commitment format valid")

            outcome_comm = commitments.get("outcome_commitment")
            if outcome_comm and len(outcome_comm) != 64:
                result.add_check("outcome_commitment_syntax", False, f"Invalid outcome hash length: {len(outcome_comm)}")
            elif outcome_comm:
                result.add_check("outcome_commitment_syntax", True, "Outcome commitment format valid")

        # ── 4. Canonical Hash Verification ───────────────────────────────────
        integrity = receipt.get("integrity", {})
        stored_hash = integrity.get("canonical_serialization_hash") or receipt.get("canonical_serialization_hash")

        payload_for_verification = copy.deepcopy(receipt)
        if "signing" in payload_for_verification and isinstance(payload_for_verification["signing"], dict):
            payload_for_verification["signing"].pop("signature", None)
        payload_for_verification.pop("signature", None)
        payload_for_verification.pop("attestations", None)
        payload_for_verification.pop("counterparty_attestations", None)
        payload_for_verification.pop("witness_attestations", None)
        payload_for_verification.pop("transparency_checkpoint", None)
        payload_for_verification.pop("transparency_proof", None)
        payload_for_verification.pop("metadata", None)
        payload_for_verification.pop("created_at", None)
        payload_for_verification.pop("updated_at", None)

        payload_without_hash = copy.deepcopy(payload_for_verification)
        if "integrity" in payload_without_hash and isinstance(payload_without_hash["integrity"], dict):
            payload_without_hash["integrity"].pop("canonical_serialization_hash", None)
        payload_without_hash.pop("canonical_serialization_hash", None)

        computed_canonical_hash = sha256_hex(canonical_encode(payload_without_hash))

        if stored_hash:
            working_copy = copy.deepcopy(receipt)
            working_copy.pop("metadata", None)
            working_copy.pop("created_at", None)
            working_copy.pop("updated_at", None)
            working_copy.pop("transparency_checkpoint", None)
            working_copy.pop("witness_attestations", None)
            working_copy.pop("counterparty_attestations", None)
            recomputed_full = sha256_hex(canonical_encode(working_copy))

            if stored_hash in (computed_canonical_hash, recomputed_full):
                result.add_check("canonical_hash", True, "Canonical serialization hash matches payload")
            else:
                result.add_check(
                    "canonical_hash",
                    False,
                    f"Canonical hash mismatch: stored={stored_hash}, computed={computed_canonical_hash}",
                )
        else:
            result.add_warning("Receipt does not contain canonical_serialization_hash")

        # ── 5. Merkle Proof Verification ─────────────────────────────────────
        merkle_root = integrity.get("merkle_root") or receipt.get("merkle_root")
        merkle_proof = integrity.get("merkle_proof") or receipt.get("merkle_proof")

        if merkle_proof and isinstance(merkle_proof, dict) and merkle_root:
            leaf_hash_hex = merkle_proof.get("leaf_hash") or stored_hash
            sibling_hashes = merkle_proof.get("sibling_hashes") or merkle_proof.get("steps") or []

            if leaf_hash_hex:
                try:
                    # Extract leaf_index from proof if available, otherwise default to 0
                    leaf_index = merkle_proof.get("leaf_index", 0)
                    tree_size = merkle_proof.get("tree_size")
                    if tree_size is None:
                        cp = receipt.get("transparency_checkpoint")
                        if isinstance(cp, dict) and cp.get("tree_size"):
                            tree_size = cp.get("tree_size")
                        else:
                            tree_size = 1

                    # Use RFC 6962 verification (normative for Phase E)
                    valid = rfc6962_verify_inclusion(
                        leaf_index=leaf_index,
                        tree_size=tree_size,
                        leaf_hash=leaf_hash_hex,
                        root_hash=merkle_root,
                        proof=sibling_hashes,
                    )

                    if not valid:
                        result.add_check(
                            "merkle_proof",
                            False,
                            f"RFC 6962 Merkle inclusion proof verification failed for root {merkle_root[:16]}...",
                        )
                    else:
                        result.add_check("merkle_proof", True, f"RFC 6962 Merkle inclusion proof verified against root {merkle_root[:16]}...")
                except Exception as exc:
                    result.add_check("merkle_proof", False, f"Merkle proof validation failed: {exc}")
            else:
                result.add_warning("Cannot verify Merkle proof without leaf_hash or canonical_hash")
        elif require_merkle:
            result.add_check("merkle_proof", False, "Receipt missing required Merkle proof or root")
        else:
            result.add_warning("No Merkle inclusion proof present to verify")

        # ── 6. Digital Signature & Trust Root Validation ─────────────────────
        signing_block = receipt.get("signing", {})
        signature_raw = None
        key_id = None
        algo = "ed25519"

        if isinstance(signing_block, dict):
            signature_raw = signing_block.get("signature")
            key_id = signing_block.get("signer_key_id") or signing_block.get("key_id")
            algo = signing_block.get("algorithm", "ed25519")
        if not signature_raw:
            signature_raw = receipt.get("signature")

        if require_signature:
            if not signature_raw:
                result.add_check("signature", False, "Missing cryptographic signature")
            else:
                pubkey = public_key_override or self.default_public_key
                key_status = "active"

                if not pubkey and key_id and key_id in self.trust_roots:
                    root = self.trust_roots[key_id]
                    pubkey = root.public_key
                    key_status = root.status
                    algo = root.algorithm

                if key_status == "revoked":
                    result.add_check("trust_root_status", False, f"Signing key '{key_id}' has been REVOKED")

                if not pubkey:
                    result.add_check(
                        "signature",
                        False,
                        f"No trusted public key found for key identifier '{key_id}'",
                    )
                else:
                    if algo.lower() != "ed25519":
                        result.add_check("signature_algorithm", False, f"Unsupported signing algorithm: {algo}")
                    else:
                        message = canonical_encode(payload_for_verification)
                        try:
                            valid_sig = verify_ed25519_signature(pubkey, signature_raw, message)
                            if valid_sig:
                                result.signature_verified = True
                                result.add_check("signature", True, f"Ed25519 signature valid using key '{key_id or 'override'}'")
                            else:
                                result.signature_verified = False
                                result.add_check("signature", False, "Ed25519 signature verification failed (mismatch)")
                        except Exception as exc:
                            result.signature_verified = False
                            result.add_check("signature", False, f"Signature verification error: {exc}")
        else:
            result.signature_verified = False
            result.verified = False  # Cryptographic verification not established
            result.add_warning("CRYPTOGRAPHIC SIGNATURE CHECK SKIPPED: This receipt is NOT cryptographically verified. Do NOT use for trust or security decisions.")
            result.add_check("signature", False, "Signature verification SKIPPED by caller (--no-signature). Structural validation only.")

        # ── 7. Transparency Checkpoint & Witness Proofs ──────────────────────
        checkpoint_data = receipt.get("transparency_checkpoint")
        witness_acks = receipt.get("witness_attestations") or []
        witness_verified_count = 0

        if checkpoint_data:
            cp_res = self.verify_checkpoint(checkpoint_data)
            for chk in cp_res.checks:
                result.checks.append(chk)
            for err in cp_res.errors:
                result.errors.append(f"checkpoint: {err}")
            if not cp_res.verified:
                result.verified = False

            # Check witness acknowledgements over the checkpoint
            for idx, ack in enumerate(witness_acks):
                ack_w_id = ack.get("witness_id") if isinstance(ack, dict) else getattr(ack, "witness_id", None)
                if allowed_witness_ids is not None and ack_w_id not in allowed_witness_ids:
                    result.add_check(f"witness_ack_{idx}", False, f"Witness '{ack_w_id}' is not in allowed witness list")
                    continue
                ack_res = self.verify_witness_acknowledgement(ack, checkpoint_data)
                if ack_res.verified:
                    witness_verified_count += 1
                else:
                    result.add_check(f"witness_ack_{idx}", False, f"Witness ACK invalid: {ack_res.errors}")

        result.transparency_assessment = {
            "checkpoint_present": checkpoint_data is not None,
            "witness_acks_present": len(witness_acks) > 0,
            "witness_acks_verified": witness_verified_count,
            "quorum_established": False,  # Verifier validates individual witness assertions, not BFT consensus quorum
            "status": "WITNESSED" if witness_verified_count > 0 else ("CHECKPOINTED" if checkpoint_data else "UNCHECKPOINTED"),
        }

        # ── 8. Counterparty Attestation Verification ─────────────────────────
        cp_attestations = receipt.get("counterparty_attestations") or []
        verified_cp_count = 0

        # Get receipt's claimed outcome for consistency check
        outcome_block = receipt.get("outcome") or {}
        receipt_outcome_status = outcome_block.get("status") or receipt.get("status")

        for idx, cp_att in enumerate(cp_attestations):
            valid_cp, detail = verify_counterparty_attestation(
                cp_att,
                counterparty_trust_roots=self.counterparty_trust_roots,
                expected_execution_id=receipt.get("execution_id"),
                expected_receipt_id=receipt_id,
                expected_outcome_status=receipt_outcome_status if receipt_outcome_status != "unknown" else None,
            )
            if valid_cp:
                verified_cp_count += 1
                result.add_check(f"counterparty_attestation_{idx}", True, detail)
            else:
                result.add_check(f"counterparty_attestation_{idx}", False, detail)
                # If contradiction detected, mark as critical
                if "CONTRADICTORY_OUTCOME_ATTESTATION" in detail:
                    result.verified = False
                    result.errors.append(f"counterparty_attestation_{idx}: {detail}")

        # ── 9. Outcome Source & Real-World Classification ────────────────────
        outcome_block = receipt.get("outcome") or {}
        outcome_source = outcome_block.get("source") or receipt.get("outcome_source") or "unknown"
        outcome_status = outcome_block.get("status") or receipt.get("status") or "unknown"

        if verified_cp_count > 0:
            outcome_source = "counterparty_attested"

        confidence = "LOW"
        if outcome_source == "counterparty_attested":
            confidence = "MAXIMAL"
        elif outcome_source == "adapter_verified":
            confidence = "HIGH"

        result.outcome_assessment = {
            "claimed_status": outcome_status,
            "source_type": outcome_source,
            "real_world_verified": outcome_source in ("adapter_verified", "counterparty_attested"),
            "confidence": confidence,
            "counterparty_attestations_verified": verified_cp_count,
        }

        if outcome_source == "agent_reported":
            result.add_warning(
                "Outcome is self-reported by the agent (source=agent_reported). "
                "Cryptographic receipt proves authorization, but does NOT prove physical or financial outcome."
            )
        elif outcome_source in ("adapter_verified", "counterparty_attested"):
            result.add_check(
                "outcome_assurance",
                True,
                f"Outcome backed by independent evidence (source={outcome_source}, confidence={confidence})",
            )

        # Cryptographic verification requires both general verification passes AND signature verification passed
        result.cryptographically_verified = bool(result.verified and result.signature_verified)

        return result


def verify_receipt_data(
    receipt: Dict[str, Any],
    public_key: Optional[str] = None,
    trust_roots: Optional[Dict[str, TrustRoot]] = None,
    witness_trust_roots: Optional[Dict[str, str]] = None,
    counterparty_trust_roots: Optional[Dict[str, str]] = None,
) -> VerificationResult:
    verifier = StandaloneReceiptVerifier(
        trust_roots=trust_roots,
        default_public_key=public_key,
        witness_trust_roots=witness_trust_roots,
        counterparty_trust_roots=counterparty_trust_roots,
    )
    return verifier.verify(receipt)


def verify_receipt_file(
    path: str | Path,
    public_key: Optional[str] = None,
    trust_roots: Optional[Dict[str, TrustRoot]] = None,
    witness_trust_roots: Optional[Dict[str, str]] = None,
    counterparty_trust_roots: Optional[Dict[str, str]] = None,
) -> VerificationResult:
    file_path = Path(path)
    if not file_path.exists():
        res = VerificationResult(verified=False, receipt_id=None, verified_at=datetime.now(timezone.utc).isoformat())
        res.add_check("file_exists", False, f"File not found: {file_path}")
        return res

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return verify_receipt_data(
        data,
        public_key=public_key,
        trust_roots=trust_roots,
        witness_trust_roots=witness_trust_roots,
        counterparty_trust_roots=counterparty_trust_roots,
    )
