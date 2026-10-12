"""
Blocklog Counterparty Attestation Protocol Implementation.

Zero-dependency standalone implementation.
Supports creation and verification of external counterparty assertions.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .canonical import canonical_encode, sha256_hex
from .crypto import decode_bytes, verify_ed25519_signature


@dataclass
class CounterpartyInfo:
    organization_id: str
    organization_name: str
    role: str  # e.g., "payment_processor", "clearing_house", "operator"
    trust_domain: Optional[str] = None


@dataclass
class AttestationAssertion:
    outcome_status: str  # "succeeded", "failed", "reversed", "settled"
    downstream_reference: str  # e.g., payment tx ID
    operation_type: str  # e.g., "financial.charge.capture"
    amount_settled_minor: Optional[int] = None
    currency: Optional[str] = None
    raw_evidence_hash: Optional[str] = None


@dataclass
class CounterpartyAttestation:
    protocol_version: str = "attestation/1.0"
    attestation_id: str = ""
    execution_id: str = ""
    receipt_id: str = ""
    request_fingerprint: str = ""
    counterparty: CounterpartyInfo = field(default_factory=lambda: CounterpartyInfo("", "", ""))
    assertion: AttestationAssertion = field(default_factory=lambda: AttestationAssertion("", "", ""))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    counterparty_key_id: str = ""
    algorithm: str = "ed25519"
    signature: str = ""

    def canonical_bytes(self) -> bytes:
        payload = {
            "protocol_version": self.protocol_version,
            "attestation_id": self.attestation_id,
            "execution_id": self.execution_id,
            "receipt_id": self.receipt_id,
            "request_fingerprint": self.request_fingerprint,
            "counterparty": asdict(self.counterparty) if isinstance(self.counterparty, CounterpartyInfo) else self.counterparty,
            "assertion": asdict(self.assertion) if isinstance(self.assertion, AttestationAssertion) else self.assertion,
            "timestamp": self.timestamp,
            "counterparty_key_id": self.counterparty_key_id,
            "algorithm": self.algorithm,
        }
        return canonical_encode(payload)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "attestation_id": self.attestation_id,
            "execution_id": self.execution_id,
            "receipt_id": self.receipt_id,
            "request_fingerprint": self.request_fingerprint,
            "counterparty": asdict(self.counterparty) if isinstance(self.counterparty, CounterpartyInfo) else self.counterparty,
            "assertion": asdict(self.assertion) if isinstance(self.assertion, AttestationAssertion) else self.assertion,
            "timestamp": self.timestamp,
            "signing": {
                "counterparty_key_id": self.counterparty_key_id,
                "algorithm": self.algorithm,
                "signature": self.signature,
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CounterpartyAttestation:
        signing = data.get("signing", {})
        cp_data = data.get("counterparty", {})
        ass_data = data.get("assertion", {})

        return cls(
            protocol_version=data.get("protocol_version", "attestation/1.0"),
            attestation_id=data.get("attestation_id", ""),
            execution_id=data.get("execution_id", ""),
            receipt_id=data.get("receipt_id", ""),
            request_fingerprint=data.get("request_fingerprint", ""),
            counterparty=CounterpartyInfo(**cp_data) if isinstance(cp_data, dict) else cp_data,
            assertion=AttestationAssertion(**ass_data) if isinstance(ass_data, dict) else ass_data,
            timestamp=data.get("timestamp", ""),
            counterparty_key_id=signing.get("counterparty_key_id", ""),
            algorithm=signing.get("algorithm", "ed25519"),
            signature=signing.get("signature", ""),
        )


class CounterpartySigner:
    """Helper for external counterparties to sign attestations."""

    def __init__(
        self,
        organization_id: str,
        organization_name: str,
        role: str,
        key_id: str,
        private_key_hex: str,
    ):
        self.organization_id = organization_id
        self.organization_name = organization_name
        self.role = role
        self.key_id = key_id
        
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        from .crypto import decode_bytes
        self._key = ed25519.Ed25519PrivateKey.from_private_bytes(decode_bytes(private_key_hex))
        self.public_key_hex = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def sign_attestation(
        self,
        attestation_id: str,
        execution_id: str,
        receipt_id: str,
        request_fingerprint: str,
        downstream_reference: str,
        outcome_status: str,
        operation_type: str,
        amount_settled_minor: Optional[int] = None,
        currency: Optional[str] = None,
        raw_evidence_hash: Optional[str] = None,
    ) -> CounterpartyAttestation:
        att = CounterpartyAttestation(
            attestation_id=attestation_id,
            execution_id=execution_id,
            receipt_id=receipt_id,
            request_fingerprint=request_fingerprint,
            counterparty=CounterpartyInfo(
                organization_id=self.organization_id,
                organization_name=self.organization_name,
                role=self.role,
            ),
            assertion=AttestationAssertion(
                outcome_status=outcome_status,
                downstream_reference=downstream_reference,
                operation_type=operation_type,
                amount_settled_minor=amount_settled_minor,
                currency=currency,
                raw_evidence_hash=raw_evidence_hash,
            ),
            timestamp=datetime.now(timezone.utc).isoformat(),
            counterparty_key_id=self.key_id,
            algorithm="ed25519",
        )
        sig_bytes = self._key.sign(att.canonical_bytes())
        att.signature = sig_bytes.hex()
        return att


def verify_counterparty_attestation(
    attestation: CounterpartyAttestation | Dict[str, Any],
    counterparty_trust_roots: Dict[str, str],  # key_id -> ed25519 public key hex
    expected_execution_id: Optional[str] = None,
    expected_receipt_id: Optional[str] = None,
    expected_fingerprint: Optional[str] = None,
    expected_outcome_status: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Verify counterparty attestation authenticity and alignment with execution.
    Returns (is_valid, detail).
    """
    if isinstance(attestation, dict):
        att = CounterpartyAttestation.from_dict(attestation)
    else:
        att = attestation

    if att.protocol_version != "attestation/1.0":
        return False, f"Unsupported attestation protocol version: {att.protocol_version}"

    if not att.signature:
        return False, "Attestation signature is missing"

    # Context binding checks
    if expected_execution_id and att.execution_id != expected_execution_id:
        return False, f"Execution ID mismatch: expected {expected_execution_id}, got {att.execution_id}"
    if expected_receipt_id and att.receipt_id != expected_receipt_id:
        return False, f"Receipt ID mismatch: expected {expected_receipt_id}, got {att.receipt_id}"
    if expected_fingerprint and att.request_fingerprint != expected_fingerprint:
        return False, f"Request fingerprint mismatch: expected {expected_fingerprint}, got {att.request_fingerprint}"

    # Outcome consistency check
    if expected_outcome_status is not None:
        if att.assertion.outcome_status != expected_outcome_status:
            return False, f"CONTRADICTORY_OUTCOME_ATTESTATION: receipt claims '{expected_outcome_status}' but attestation asserts '{att.assertion.outcome_status}'"

    # Trust root check
    pub_hex = counterparty_trust_roots.get(att.counterparty_key_id)
    if not pub_hex:
        return False, f"Counterparty key '{att.counterparty_key_id}' not found in trusted counterparty roots"

    # Ed25519 Signature check
    valid_sig = verify_ed25519_signature(pub_hex, att.signature, att.canonical_bytes())
    if not valid_sig:
        return False, "Counterparty signature verification failed"

    return True, f"Valid attestation from {att.counterparty.organization_name} ({att.assertion.outcome_status})"
