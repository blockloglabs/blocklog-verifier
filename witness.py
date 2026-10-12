"""
Blocklog Independent Witnessing Protocol and Implementation.

Zero-dependency standalone witness interface and implementation.
Operates outside the primary Blocklog trust boundary.
Detects:
- Tree-size rollback
- Forking / split-view equivocation attacks
- Inconsistent history extensions via RFC 6962
- Unauthorized or forged checkpoint signatures
"""
from __future__ import annotations

import json
import os
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .canonical import canonical_encode, sha256_hex
from .crypto import decode_bytes, verify_ed25519_signature
from .merkle import rfc6962_verify_consistency, sha256_digest


@dataclass
class WitnessState:
    log_id: str
    tree_size: int
    root_hash: str
    checkpoint_id: str
    timestamp: str


@dataclass
class WitnessAcknowledgement:
    protocol_version: str = "witness-ack/1.0"
    witness_id: str = ""
    log_id: str = ""
    tree_size: int = 0
    root_hash: str = ""
    checkpoint_id: str = ""
    acknowledged_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    witness_key_id: str = ""
    signature: str = ""

    def canonical_bytes(self) -> bytes:
        payload = {
            "protocol_version": self.protocol_version,
            "witness_id": self.witness_id,
            "log_id": self.log_id,
            "tree_size": self.tree_size,
            "root_hash": self.root_hash.lower(),
            "checkpoint_id": self.checkpoint_id,
            "acknowledged_at": self.acknowledged_at,
            "witness_key_id": self.witness_key_id,
        }
        return canonical_encode(payload)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WitnessRejection:
    protocol_version: str = "witness-rejection/1.0"
    witness_id: str = ""
    log_id: str = ""
    reason_code: str = ""  # FORK_DETECTED, TREE_ROLLBACK, INVALID_SIGNATURE, INCONSISTENT_HISTORY
    detail: str = ""
    observed_tree_size: int = 0
    observed_root_hash: str = ""
    last_known_tree_size: int = 0
    last_known_root_hash: str = ""
    checkpoint_id: str = ""
    rejected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    witness_key_id: str = ""
    signature: str = ""

    def canonical_bytes(self) -> bytes:
        payload = {
            "protocol_version": self.protocol_version,
            "witness_id": self.witness_id,
            "log_id": self.log_id,
            "reason_code": self.reason_code,
            "detail": self.detail,
            "observed_tree_size": self.observed_tree_size,
            "observed_root_hash": self.observed_root_hash.lower(),
            "last_known_tree_size": self.last_known_tree_size,
            "last_known_root_hash": self.last_known_root_hash.lower(),
            "checkpoint_id": self.checkpoint_id,
            "rejected_at": self.rejected_at,
            "witness_key_id": self.witness_key_id,
        }
        return canonical_encode(payload)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Storage Interfaces ────────────────────────────────────────────────────────

class WitnessStorage(ABC):
    """Abstract durable storage for witness state."""

    @abstractmethod
    def get_state(self, log_id: str) -> Optional[WitnessState]:
        """Retrieve last accepted state for a log."""

    @abstractmethod
    def save_state(self, state: WitnessState) -> None:
        """Persist newly accepted state durably."""

    @abstractmethod
    def get_state_chain(self, log_id: str) -> list[WitnessState]:
        """Retrieve full state chain for integrity verification."""


class MemoryWitnessStorage(WitnessStorage):
    """Ephemeral in-memory storage for testing."""

    def __init__(self):
        self._states: Dict[str, WitnessState] = {}
        self._chains: Dict[str, list[WitnessState]] = {}

    def get_state(self, log_id: str) -> Optional[WitnessState]:
        return self._states.get(log_id)

    def save_state(self, state: WitnessState) -> None:
        self._states[state.log_id] = state
        if state.log_id not in self._chains:
            self._chains[state.log_id] = []
        self._chains[state.log_id].append(state)

    def get_state_chain(self, log_id: str) -> list[WitnessState]:
        return self._chains.get(log_id, [])


class SqliteWitnessStorage(WitnessStorage):
    """Durable SQLite storage with tamper-evident state chain for witness observations."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS witness_states (
                    log_id TEXT PRIMARY KEY,
                    tree_size INTEGER NOT NULL,
                    root_hash TEXT NOT NULL,
                    checkpoint_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    state_hash TEXT NOT NULL,
                    prev_state_hash TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS witness_state_chain (
                    log_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    tree_size INTEGER NOT NULL,
                    root_hash TEXT NOT NULL,
                    checkpoint_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    state_hash TEXT NOT NULL,
                    PRIMARY KEY (log_id, sequence)
                )
            """)
            conn.commit()

    def _compute_state_hash(self, state: WitnessState, prev_state_hash: Optional[str]) -> str:
        """Compute tamper-evident hash of state chained to previous state."""
        payload = {
            "log_id": state.log_id,
            "tree_size": state.tree_size,
            "root_hash": state.root_hash.lower(),
            "checkpoint_id": state.checkpoint_id,
            "timestamp": state.timestamp,
            "prev_state_hash": prev_state_hash,
        }
        return sha256_digest(canonical_encode(payload)).hex()

    def get_state(self, log_id: str) -> Optional[WitnessState]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT log_id, tree_size, root_hash, checkpoint_id, timestamp, state_hash, prev_state_hash FROM witness_states WHERE log_id = ?",
                (log_id,),
            )
            row = cursor.fetchone()
            if row:
                state = WitnessState(
                    log_id=row[0],
                    tree_size=row[1],
                    root_hash=row[2],
                    checkpoint_id=row[3],
                    timestamp=row[4],
                )
                # Verify integrity of loaded state
                expected_hash = self._compute_state_hash(state, row[6])
                if expected_hash != row[5]:
                    raise ValueError(f"Witness state integrity check failed for log '{log_id}': state hash mismatch")
                return state
            return None

    def save_state(self, state: WitnessState) -> None:
        with sqlite3.connect(self.db_path) as conn:
            # Get previous state hash for chaining
            cursor = conn.cursor()
            cursor.execute("SELECT state_hash FROM witness_states WHERE log_id = ?", (state.log_id,))
            row = cursor.fetchone()
            prev_state_hash = row[0] if row else None

            # Compute new state hash
            state_hash = self._compute_state_hash(state, prev_state_hash)

            # Insert/update main state
            conn.execute("""
                INSERT INTO witness_states (log_id, tree_size, root_hash, checkpoint_id, timestamp, state_hash, prev_state_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(log_id) DO UPDATE SET
                    tree_size = excluded.tree_size,
                    root_hash = excluded.root_hash,
                    checkpoint_id = excluded.checkpoint_id,
                    timestamp = excluded.timestamp,
                    state_hash = excluded.state_hash,
                    prev_state_hash = excluded.prev_state_hash
            """, (state.log_id, state.tree_size, state.root_hash, state.checkpoint_id, state.timestamp, state_hash, prev_state_hash))

            # Append to chain
            cursor.execute("SELECT COALESCE(MAX(sequence), 0) FROM witness_state_chain WHERE log_id = ?", (state.log_id,))
            seq = (cursor.fetchone()[0] or 0) + 1
            conn.execute("""
                INSERT INTO witness_state_chain (log_id, sequence, tree_size, root_hash, checkpoint_id, timestamp, state_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (state.log_id, seq, state.tree_size, state.root_hash, state.checkpoint_id, state.timestamp, state_hash))

            conn.commit()

    def get_state_chain(self, log_id: str) -> list[WitnessState]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT log_id, tree_size, root_hash, checkpoint_id, timestamp FROM witness_state_chain WHERE log_id = ? ORDER BY sequence",
                (log_id,),
            )
            return [
                WitnessState(log_id=row[0], tree_size=row[1], root_hash=row[2], checkpoint_id=row[3], timestamp=row[4])
                for row in cursor.fetchall()
            ]


# ── Witness Core ─────────────────────────────────────────────────────────────

def canonicalize_checkpoint_for_verification(checkpoint: Dict[str, Any]) -> bytes:
    """Canonical bytes of checkpoint payload for signature check."""
    signing_block = checkpoint.get("signing", {})
    payload = {
        "protocol_version": checkpoint.get("protocol_version", "checkpoint/1.0"),
        "log_id": checkpoint["log_id"],
        "tree_size": checkpoint["tree_size"],
        "root_hash": checkpoint["root_hash"].lower(),
        "timestamp": checkpoint["timestamp"],
        "checkpoint_id": checkpoint["checkpoint_id"],
        "previous_root_hash": checkpoint.get("previous_root_hash"),
        "signer_key_id": signing_block.get("signer_key_id", ""),
        "algorithm": signing_block.get("algorithm", "ed25519"),
    }
    return canonical_encode(payload)


class IndependentWitness:
    """
    Independent transparency log witness.
    Evaluates checkpoints, enforces monotonicity, verifies consistency,
    and signs cryptographic acknowledgements.
    """

    def __init__(
        self,
        witness_id: str,
        witness_key_id: str,
        witness_private_key_hex: str,
        log_trust_roots: Dict[str, Dict[str, str]],  # signer_key_id -> {"public_key": hex, "status": "active"|"deprecated"|"revoked"}
        storage: Optional[WitnessStorage] = None,
    ):
        self.witness_id = witness_id
        self.witness_key_id = witness_key_id
        self._private_key_bytes = decode_bytes(witness_private_key_hex)
        self.log_trust_roots = log_trust_roots
        self.storage = storage or MemoryWitnessStorage()

        # Initialize Ed25519 key for signing ACKs
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        self._signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(self._private_key_bytes)
        self.public_key_hex = self._signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def _sign_ack(self, ack: WitnessAcknowledgement) -> WitnessAcknowledgement:
        sig_bytes = self._signing_key.sign(ack.canonical_bytes())
        ack.signature = sig_bytes.hex()
        return ack

    def _sign_rejection(self, rej: WitnessRejection) -> WitnessRejection:
        sig_bytes = self._signing_key.sign(rej.canonical_bytes())
        rej.signature = sig_bytes.hex()
        return rej

    def observe_checkpoint(
        self,
        checkpoint: Dict[str, Any],
        consistency_proof: Optional[List[str]] = None,
    ) -> WitnessAcknowledgement | WitnessRejection:
        """
        Evaluate an incoming checkpoint.
        Returns signed WitnessAcknowledgement on success, or signed WitnessRejection on failure.
        """
        log_id = checkpoint.get("log_id")
        checkpoint_id = checkpoint.get("checkpoint_id", "")
        tree_size = checkpoint.get("tree_size")
        root_hash = checkpoint.get("root_hash", "").lower()

        if not log_id or tree_size is None or not root_hash:
            return self._sign_rejection(WitnessRejection(
                witness_id=self.witness_id,
                log_id=str(log_id),
                reason_code="MALFORMED_CHECKPOINT",
                detail="Checkpoint missing required fields (log_id, tree_size, root_hash)",
                checkpoint_id=checkpoint_id,
                witness_key_id=self.witness_key_id,
            ))

        # ── 1. Checkpoint Signature Verification ─────────────────────────────
        signing = checkpoint.get("signing", {})
        signer_key_id = signing.get("signer_key_id")
        sig_raw = signing.get("signature")

        if not signer_key_id or not sig_raw:
            return self._sign_rejection(WitnessRejection(
                witness_id=self.witness_id,
                log_id=log_id,
                reason_code="INVALID_SIGNATURE",
                detail="Missing signer_key_id or signature in checkpoint",
                checkpoint_id=checkpoint_id,
                observed_tree_size=tree_size,
                observed_root_hash=root_hash,
                witness_key_id=self.witness_key_id,
            ))

        trust_root = self.log_trust_roots.get(signer_key_id)
        if not trust_root:
            return self._sign_rejection(WitnessRejection(
                witness_id=self.witness_id,
                log_id=log_id,
                reason_code="UNTRUSTED_SIGNER",
                detail=f"Signer key '{signer_key_id}' not in witness trust roots",
                checkpoint_id=checkpoint_id,
                observed_tree_size=tree_size,
                observed_root_hash=root_hash,
                witness_key_id=self.witness_key_id,
            ))

        # Support both legacy format (str public_key) and new format (dict with public_key and status)
        if isinstance(trust_root, str):
            log_pubkey = trust_root
            key_status = "active"
        else:
            log_pubkey = trust_root.get("public_key")
            key_status = trust_root.get("status", "active")

        if key_status == "revoked":
            return self._sign_rejection(WitnessRejection(
                witness_id=self.witness_id,
                log_id=log_id,
                reason_code="REVOKED_SIGNER",
                detail=f"Signer key '{signer_key_id}' is revoked",
                checkpoint_id=checkpoint_id,
                observed_tree_size=tree_size,
                observed_root_hash=root_hash,
                witness_key_id=self.witness_key_id,
            ))

        if not log_pubkey:
            return self._sign_rejection(WitnessRejection(
                witness_id=self.witness_id,
                log_id=log_id,
                reason_code="UNTRUSTED_SIGNER",
                detail=f"Signer key '{signer_key_id}' has no public key in trust roots",
                checkpoint_id=checkpoint_id,
                observed_tree_size=tree_size,
                observed_root_hash=root_hash,
                witness_key_id=self.witness_key_id,
            ))

        message = canonicalize_checkpoint_for_verification(checkpoint)
        if not verify_ed25519_signature(log_pubkey, sig_raw, message):
            return self._sign_rejection(WitnessRejection(
                witness_id=self.witness_id,
                log_id=log_id,
                reason_code="INVALID_SIGNATURE",
                detail="Checkpoint Ed25519 signature verification failed",
                checkpoint_id=checkpoint_id,
                observed_tree_size=tree_size,
                observed_root_hash=root_hash,
                witness_key_id=self.witness_key_id,
            ))

        # ── 2. Monotonic State & Anti-Equivocation Check ─────────────────────
        last_state = self.storage.get_state(log_id)

        if last_state is None:
            # First checkpoint observed for this log
            new_state = WitnessState(
                log_id=log_id,
                tree_size=tree_size,
                root_hash=root_hash,
                checkpoint_id=checkpoint_id,
                timestamp=checkpoint.get("timestamp", datetime.now(timezone.utc).isoformat()),
            )
            self.storage.save_state(new_state)

            ack = WitnessAcknowledgement(
                witness_id=self.witness_id,
                log_id=log_id,
                tree_size=tree_size,
                root_hash=root_hash,
                checkpoint_id=checkpoint_id,
                witness_key_id=self.witness_key_id,
            )
            return self._sign_ack(ack)

        # Case A: Tree Rollback (tree_size < last_state.tree_size)
        if tree_size < last_state.tree_size:
            return self._sign_rejection(WitnessRejection(
                witness_id=self.witness_id,
                log_id=log_id,
                reason_code="TREE_ROLLBACK",
                detail=f"Checkpoint tree_size {tree_size} is smaller than previously observed size {last_state.tree_size}",
                checkpoint_id=checkpoint_id,
                observed_tree_size=tree_size,
                observed_root_hash=root_hash,
                last_known_tree_size=last_state.tree_size,
                last_known_root_hash=last_state.root_hash,
                witness_key_id=self.witness_key_id,
            ))

        # Case B: Identical tree size (tree_size == last_state.tree_size)
        if tree_size == last_state.tree_size:
            if root_hash != last_state.root_hash:
                # Critical security violation: Split-view / Fork attack
                return self._sign_rejection(WitnessRejection(
                    witness_id=self.witness_id,
                    log_id=log_id,
                    reason_code="FORK_DETECTED",
                    detail=f"Conflicting root for identical tree size {tree_size}. Expected {last_state.root_hash}, observed {root_hash}",
                    checkpoint_id=checkpoint_id,
                    observed_tree_size=tree_size,
                    observed_root_hash=root_hash,
                    last_known_tree_size=last_state.tree_size,
                    last_known_root_hash=last_state.root_hash,
                    witness_key_id=self.witness_key_id,
                ))

            # Idempotent re-observation of identical checkpoint
            ack = WitnessAcknowledgement(
                witness_id=self.witness_id,
                log_id=log_id,
                tree_size=tree_size,
                root_hash=root_hash,
                checkpoint_id=checkpoint_id,
                witness_key_id=self.witness_key_id,
            )
            return self._sign_ack(ack)

        # Case C: Tree Growth (tree_size > last_state.tree_size)
        # Must verify RFC 6962 consistency proof
        if not consistency_proof:
            return self._sign_rejection(WitnessRejection(
                witness_id=self.witness_id,
                log_id=log_id,
                reason_code="MISSING_CONSISTENCY_PROOF",
                detail=f"Tree grew from {last_state.tree_size} to {tree_size} without supplying a consistency proof",
                checkpoint_id=checkpoint_id,
                observed_tree_size=tree_size,
                observed_root_hash=root_hash,
                last_known_tree_size=last_state.tree_size,
                last_known_root_hash=last_state.root_hash,
                witness_key_id=self.witness_key_id,
            ))

        valid_ext = rfc6962_verify_consistency(
            m=last_state.tree_size,
            n=tree_size,
            root_m=last_state.root_hash,
            root_n=root_hash,
            proof=consistency_proof,
        )

        if not valid_ext:
            return self._sign_rejection(WitnessRejection(
                witness_id=self.witness_id,
                log_id=log_id,
                reason_code="INCONSISTENT_HISTORY",
                detail=f"RFC 6962 consistency proof failed between size {last_state.tree_size} and {tree_size}",
                checkpoint_id=checkpoint_id,
                observed_tree_size=tree_size,
                observed_root_hash=root_hash,
                last_known_tree_size=last_state.tree_size,
                last_known_root_hash=last_state.root_hash,
                witness_key_id=self.witness_key_id,
            ))

        # Successfully verified append-only extension; persist state
        updated_state = WitnessState(
            log_id=log_id,
            tree_size=tree_size,
            root_hash=root_hash,
            checkpoint_id=checkpoint_id,
            timestamp=checkpoint.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )
        self.storage.save_state(updated_state)

        ack = WitnessAcknowledgement(
            witness_id=self.witness_id,
            log_id=log_id,
            tree_size=tree_size,
            root_hash=root_hash,
            checkpoint_id=checkpoint_id,
            witness_key_id=self.witness_key_id,
        )
        return self._sign_ack(ack)
