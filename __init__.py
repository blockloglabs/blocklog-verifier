"""
Blocklog Standalone Receipt & Transparency Verifier Library

Zero backend dependencies. Operates completely offline.
Depends only on Python standard library and standard `cryptography` package.
"""

from verifier.core import (
    StandaloneReceiptVerifier,
    VerificationResult,
    VerificationCheck,
    TrustRoot,
    verify_receipt_data,
    verify_receipt_file,
)
from verifier.canonical import (
    canonical_encode,
    nfc_normalize,
    sha256_hex,
)
from verifier.crypto import (
    verify_ed25519_signature,
    decode_bytes,
)
from verifier.merkle import (
    rfc6962_leaf_hash,
    rfc6962_node_hash,
    rfc6962_tree_hash,
    rfc6962_inclusion_proof,
    rfc6962_verify_inclusion,
    rfc6962_consistency_proof,
    rfc6962_verify_consistency,
)
from verifier.witness import (
    IndependentWitness,
    WitnessState,
    WitnessAcknowledgement,
    WitnessRejection,
    WitnessStorage,
    MemoryWitnessStorage,
    SqliteWitnessStorage,
)
from verifier.attestation import (
    CounterpartyAttestation,
    CounterpartySigner,
    verify_counterparty_attestation,
)

__version__ = "2.0.0"

__all__ = [
    "StandaloneReceiptVerifier",
    "VerificationResult",
    "VerificationCheck",
    "TrustRoot",
    "verify_receipt_data",
    "verify_receipt_file",
    "canonical_encode",
    "nfc_normalize",
    "sha256_hex",
    "verify_ed25519_signature",
    "decode_bytes",
    "rfc6962_leaf_hash",
    "rfc6962_node_hash",
    "rfc6962_tree_hash",
    "rfc6962_inclusion_proof",
    "rfc6962_verify_inclusion",
    "rfc6962_consistency_proof",
    "rfc6962_verify_consistency",
    "IndependentWitness",
    "WitnessState",
    "WitnessAcknowledgement",
    "WitnessRejection",
    "WitnessStorage",
    "MemoryWitnessStorage",
    "SqliteWitnessStorage",
    "CounterpartyAttestation",
    "CounterpartySigner",
    "verify_counterparty_attestation",
]
