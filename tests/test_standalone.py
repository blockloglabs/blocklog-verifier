"""
Standalone unit tests for blocklog-verifier package.
Requires ONLY `pytest` and `cryptography`. Zero backend or database dependencies.
"""
import copy
from datetime import datetime, timezone
import json
import pytest
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
    rfc6962_verify_inclusion,
    rfc6962_consistency_proof,
    rfc6962_verify_consistency,
    IndependentWitness,
    MemoryWitnessStorage,
    CounterpartySigner,
    verify_receipt_data,
)
from verifier.witness import WitnessAcknowledgement, WitnessRejection


@pytest.fixture
def keys():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return priv, pub


def test_standalone_receipt_verification(keys):
    priv, pub = keys
    receipt = {
        "version": "1.0",
        "receipt_id": "rcpt_test_01",
        "execution_id": "exec_test_01",
        "realm": {"company_id": "test_corp"},
        "policy": {
            "policy_id": "pol_1",
            "decision": "APPROVED",
        },
        "execution": {
            "processor": "test_processor",
            "action_type": "test_action",
        },
        "commitments": {
            "execution_commitment": sha256_hex("exec_commit"),
        },
        "outcome": {
            "status": "succeeded",
            "source": "adapter_verified",
        },
        "integrity": {},
        "signing": {
            "signer_key_id": "key_1",
            "algorithm": "ed25519",
        },
    }

    # Canonical hash & signature
    receipt_for_hash = copy.deepcopy(receipt)
    receipt_for_hash["signing"].pop("signature", None)
    can_hash = sha256_hex(canonical_encode(receipt_for_hash))
    receipt["integrity"]["canonical_serialization_hash"] = can_hash

    to_sign = copy.deepcopy(receipt)
    to_sign["signing"].pop("signature", None)
    receipt["signing"]["signature"] = priv.sign(canonical_encode(to_sign)).hex()

    verifier = StandaloneReceiptVerifier(
        trust_roots={"key_1": TrustRoot("key_1", pub)}
    )
    result = verifier.verify(receipt)
    assert result.verified is True
    assert result.outcome_assessment["confidence"] == "HIGH"


def test_standalone_merkle_consistency():
    leaves = [rfc6962_leaf_hash(f"leaf_{i}") for i in range(8)]
    root4 = rfc6962_tree_hash(leaves[:4]).hex()
    root8 = rfc6962_tree_hash(leaves[:8]).hex()

    proof = rfc6962_consistency_proof(4, leaves)
    assert rfc6962_verify_consistency(4, 8, root4, root8, proof) is True
    # Tampered root must fail
    assert rfc6962_verify_consistency(4, 8, root4, "00" * 32, proof) is False


def test_standalone_witness_anti_equivocation(keys):
    bl_priv, bl_pub = keys
    wit_priv = ed25519.Ed25519PrivateKey.generate()
    wit_priv_hex = wit_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()

    witness = IndependentWitness(
        witness_id="wit_standalone",
        witness_key_id="wit_k",
        witness_private_key_hex=wit_priv_hex,
        log_trust_roots={"bl_k": bl_pub},
        storage=MemoryWitnessStorage(),
    )

    cp_payload = {
        "protocol_version": "checkpoint/1.0",
        "log_id": "test_log",
        "tree_size": 10,
        "root_hash": "aa" * 32,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checkpoint_id": "cp_1",
        "previous_root_hash": None,
        "signing": {
            "signer_key_id": "bl_k",
            "algorithm": "ed25519",
        },
    }
    msg = canonical_encode({
        "protocol_version": cp_payload["protocol_version"],
        "log_id": cp_payload["log_id"],
        "tree_size": cp_payload["tree_size"],
        "root_hash": cp_payload["root_hash"].lower(),
        "timestamp": cp_payload["timestamp"],
        "checkpoint_id": cp_payload["checkpoint_id"],
        "previous_root_hash": cp_payload["previous_root_hash"],
        "signer_key_id": cp_payload["signing"]["signer_key_id"],
        "algorithm": cp_payload["signing"]["algorithm"],
    })
    cp_payload["signing"]["signature"] = bl_priv.sign(msg).hex()

    ack = witness.observe_checkpoint(cp_payload)
    assert ack.signature != ""

    # Fork attempt with different root on same size 10
    fork_cp = copy.deepcopy(cp_payload)
    fork_cp["checkpoint_id"] = "cp_fork"
    fork_cp["root_hash"] = "bb" * 32
    fork_msg = canonical_encode({
        "protocol_version": fork_cp["protocol_version"],
        "log_id": fork_cp["log_id"],
        "tree_size": fork_cp["tree_size"],
        "root_hash": fork_cp["root_hash"].lower(),
        "timestamp": fork_cp["timestamp"],
        "checkpoint_id": "cp_fork",
        "previous_root_hash": fork_cp["previous_root_hash"],
        "signer_key_id": fork_cp["signing"]["signer_key_id"],
        "algorithm": fork_cp["signing"]["algorithm"],
    })
    fork_cp["signing"]["signature"] = bl_priv.sign(fork_msg).hex()
    rej = witness.observe_checkpoint(fork_cp)
    assert rej.reason_code == "FORK_DETECTED"


def test_no_signature_flag_semantics(keys):
    """When require_signature=False, verifier must distinguish structural validity from cryptographic verification."""
    priv, pub = keys
    receipt = {
        "version": "1.0",
        "receipt_id": "rcpt_syntax_only",
        "execution_id": "exec_syntax_only",
        "realm": {"company_id": "acme"},
        "policy": {"policy_id": "pol_1", "decision": "APPROVED"},
        "execution": {"processor": "test", "action_type": "test"},
        "commitments": {"execution_commitment": sha256_hex("test")},
        "outcome": {"status": "succeeded", "source": "adapter_verified"},
        "integrity": {},
        "signing": {"signer_key_id": "k1", "algorithm": "ed25519"},
    }
    receipt_copy = copy.deepcopy(receipt)
    can_hash = sha256_hex(canonical_encode(receipt_copy))
    receipt["integrity"]["canonical_serialization_hash"] = can_hash

    verifier = StandaloneReceiptVerifier()
    res = verifier.verify(receipt, require_signature=False)

    # Must be structurally valid
    assert res.structural_valid is True
    # But NOT verified or cryptographically verified
    assert res.verified is False
    assert res.signature_verified is False
    assert res.cryptographically_verified is False
    # Explicit warning must be present
    assert any("SIGNATURE CHECK SKIPPED" in w for w in res.warnings)


# ── Adversarial Security & Boundary Tests ────────────────────────────────────


def test_adversarial_malformed_receipt_envelopes():
    """Ensure missing required fields or malformed commitments fail with structural_valid=False."""
    verifier = StandaloneReceiptVerifier()

    # 1. Missing version
    res = verifier.verify({"execution_id": "e1"}, require_signature=False)
    assert res.verified is False
    assert res.structural_valid is False
    assert any("schema_version" in e for e in res.errors)

    # 2. Unsupported version
    res = verifier.verify({"version": "99.0", "execution_id": "e1"}, require_signature=False)
    assert res.verified is False
    assert res.structural_valid is False

    # 3. Missing required fields
    res = verifier.verify({"version": "1.0", "execution_id": "e1"}, require_signature=False)
    assert res.verified is False
    assert res.structural_valid is False
    assert any("required_fields" in e for e in res.errors)

    # 4. Malformed commitments length
    res = verifier.verify({
        "version": "1.0",
        "execution_id": "e1",
        "policy": {},
        "execution": {},
        "commitments": {"execution_commitment": "short_hash"},
    }, require_signature=False)
    assert res.verified is False
    assert res.structural_valid is False


def test_adversarial_signature_tampering(keys):
    """Tampering with signature bytes or message payload must immediately fail verification."""
    priv, pub = keys
    receipt = {
        "version": "1.0",
        "receipt_id": "rcpt_tamper",
        "execution_id": "exec_tamper",
        "policy": {"policy_id": "p1"},
        "execution": {"action": "transfer"},
        "commitments": {"execution_commitment": sha256_hex("comm")},
        "integrity": {},
        "signing": {"signer_key_id": "k1", "algorithm": "ed25519"},
    }
    # Compute canonical hash
    receipt_for_hash = copy.deepcopy(receipt)
    receipt_for_hash["signing"].pop("signature", None)
    can_hash = sha256_hex(canonical_encode(receipt_for_hash))
    receipt["integrity"]["canonical_serialization_hash"] = can_hash

    # Sign canonical payload
    to_sign = copy.deepcopy(receipt)
    to_sign["signing"].pop("signature", None)
    receipt["signing"]["signature"] = priv.sign(canonical_encode(to_sign)).hex()

    verifier = StandaloneReceiptVerifier(trust_roots={"k1": TrustRoot("k1", pub)})

    # Baseline valid
    assert verifier.verify(receipt).verified is True

    # Tamper payload
    tampered_payload = copy.deepcopy(receipt)
    tampered_payload["execution"]["action"] = "malicious_action"
    res_tamper = verifier.verify(tampered_payload)
    assert res_tamper.verified is False
    assert res_tamper.cryptographically_verified is False

    # Corrupt signature hex
    tampered_sig = copy.deepcopy(receipt)
    tampered_sig["signing"]["signature"] = "00" * 64
    res_sig = verifier.verify(tampered_sig)
    assert res_sig.verified is False
    assert res_sig.signature_verified is False


def test_adversarial_revoked_key(keys):
    """Signer key with status='revoked' must be rejected even if cryptographic signature is valid."""
    priv, pub = keys
    receipt = {
        "version": "1.0",
        "receipt_id": "rcpt_revoked",
        "execution_id": "exec_revoked",
        "policy": {},
        "execution": {},
        "commitments": {"execution_commitment": sha256_hex("comm")},
        "integrity": {},
        "signing": {"signer_key_id": "revoked_k", "algorithm": "ed25519"},
    }
    receipt_for_hash = copy.deepcopy(receipt)
    receipt_for_hash["signing"].pop("signature", None)
    can_hash = sha256_hex(canonical_encode(receipt_for_hash))
    receipt["integrity"]["canonical_serialization_hash"] = can_hash

    to_sign = copy.deepcopy(receipt)
    to_sign["signing"].pop("signature", None)
    receipt["signing"]["signature"] = priv.sign(canonical_encode(to_sign)).hex()

    # Trust root has status='revoked'
    verifier = StandaloneReceiptVerifier(
        trust_roots={"revoked_k": TrustRoot("revoked_k", pub, status="revoked")}
    )
    res = verifier.verify(receipt)
    assert res.verified is False
    assert res.cryptographically_verified is False
    assert any("REVOKED" in e for e in res.errors)


def test_adversarial_merkle_boundary_and_tampering():
    """Verify empty trees, single-leaf trees, uneven sizes, and invalid audit paths."""
    from verifier.merkle import rfc6962_verify_inclusion

    # 1. Empty tree (tree_size = 0)
    assert rfc6962_verify_inclusion(0, 0, "00" * 32, "00" * 32, []) is False

    # 2. Single-leaf tree (tree_size = 1)
    single_leaf = rfc6962_leaf_hash("only_leaf")
    single_root = rfc6962_tree_hash([single_leaf])
    assert single_root == single_leaf
    assert rfc6962_verify_inclusion(0, 1, single_leaf, single_root, []) is True
    # Non-empty proof for tree_size=1 is invalid
    assert rfc6962_verify_inclusion(0, 1, single_leaf, single_root, [{"position": "left", "hash": "00" * 32}]) is False

    # 3. Out-of-bounds leaf index
    assert rfc6962_verify_inclusion(-1, 3, "00" * 32, "00" * 32, []) is False
    assert rfc6962_verify_inclusion(3, 3, "00" * 32, "00" * 32, []) is False

    # 4. Uneven tree size (n=7)
    leaves7 = [rfc6962_leaf_hash(f"leaf_{i}") for i in range(7)]
    root7 = rfc6962_tree_hash(leaves7)
    for i in range(7):
        proof = rfc6962_inclusion_proof(i, leaves7)
        assert rfc6962_verify_inclusion(i, 7, leaves7[i], root7, proof) is True

        # Incorrect leaf index with same proof must fail
        wrong_idx = (i + 1) % 7
        assert rfc6962_verify_inclusion(wrong_idx, 7, leaves7[i], root7, proof) is False

        # Tampered sibling hash must fail
        tampered_proof = copy.deepcopy(proof)
        if tampered_proof:
            tampered_proof[0]["hash"] = "00" * 32
            assert rfc6962_verify_inclusion(i, 7, leaves7[i], root7, tampered_proof) is False


def test_adversarial_counterparty_attestation_replay_and_binding(keys):
    """Counterparty attestation replayed for different execution_id or fingerprint must fail."""
    from verifier.attestation import verify_counterparty_attestation

    priv, pub = keys
    cp_signer = CounterpartySigner(
        organization_id="org_bank",
        organization_name="Federal Reserve Bank",
        role="clearing_house",
        key_id="bank_k1",
        private_key_hex=priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex(),
    )

    att = cp_signer.sign_attestation(
        attestation_id="att_1",
        execution_id="exec_legit",
        receipt_id="rcpt_legit",
        request_fingerprint="fp_legit_12345",
        downstream_reference="txn_abc",
        outcome_status="succeeded",
        operation_type="wire.transfer",
    )

    trust_roots = {"bank_k1": pub}

    # Baseline valid
    valid, _ = verify_counterparty_attestation(
        att,
        counterparty_trust_roots=trust_roots,
        expected_execution_id="exec_legit",
        expected_receipt_id="rcpt_legit",
        expected_fingerprint="fp_legit_12345",
    )
    assert valid is True

    # Replay on different execution_id
    valid_replay_exec, msg = verify_counterparty_attestation(
        att,
        counterparty_trust_roots=trust_roots,
        expected_execution_id="exec_ATTACKER",
        expected_receipt_id="rcpt_legit",
    )
    assert valid_replay_exec is False
    assert "Execution ID mismatch" in msg

    # Replay on different receipt_id
    valid_replay_rcpt, msg = verify_counterparty_attestation(
        att,
        counterparty_trust_roots=trust_roots,
        expected_execution_id="exec_legit",
        expected_receipt_id="rcpt_ATTACKER",
    )
    assert valid_replay_rcpt is False
    assert "Receipt ID mismatch" in msg

    # Replay on different fingerprint
    valid_replay_fp, msg = verify_counterparty_attestation(
        att,
        counterparty_trust_roots=trust_roots,
        expected_fingerprint="fp_TAMPERED",
    )
    assert valid_replay_fp is False
    assert "Request fingerprint mismatch" in msg

    # Untrusted counterparty key
    valid_untrusted, msg = verify_counterparty_attestation(
        att,
        counterparty_trust_roots={"other_key": pub},
    )
    assert valid_untrusted is False
    assert "not found in trusted" in msg


def test_independent_rfc6962_differential_vectors():
    """Differential verification of inclusion and consistency proofs against direct reference logic."""
    import hashlib

    def ref_split(n):
        return 1 << ((n - 1).bit_length() - 1)

    def ref_mth(d):
        if len(d) == 0:
            return hashlib.sha256(b"").digest()
        if len(d) == 1:
            return hashlib.sha256(b"\x00" + d[0]).digest()
        k = ref_split(len(d))
        return hashlib.sha256(b"\x01" + ref_mth(d[:k]) + ref_mth(d[k:])).digest()

    def ref_path(m, d):
        n = len(d)
        if n <= 1:
            return []
        k = ref_split(n)
        if m < k:
            return ref_path(m, d[:k]) + [("right", ref_mth(d[k:]))]
        else:
            return ref_path(m - k, d[k:]) + [("left", ref_mth(d[:k]))]

    # Verify across multiple sizes including power of two, primes, and uneven sizes
    for n in (1, 2, 3, 4, 5, 7, 8, 15, 16, 17):
        data = [f"item_{i}".encode("utf-8") for i in range(n)]
        leaves = [rfc6962_leaf_hash(d) for d in data]

        # Tree hash match
        assert rfc6962_tree_hash(leaves) == ref_mth(data)

        # Inclusion proofs match reference
        for m in range(n):
            expected_path = ref_path(m, data)
            actual_proof = rfc6962_inclusion_proof(m, leaves)
            assert len(actual_proof) == len(expected_path)
            for (exp_pos, exp_hash), act_step in zip(expected_path, actual_proof):
                assert exp_pos == act_step["position"]
                assert exp_hash.hex() == act_step["hash"]

            # Inclusion verification
            assert rfc6962_verify_inclusion(m, n, leaves[m], ref_mth(data), actual_proof) is True

            # Inverted position must fail
            if actual_proof:
                bad_dir = copy.deepcopy(actual_proof)
                bad_dir[0]["position"] = "left" if bad_dir[0]["position"] == "right" else "right"
                assert rfc6962_verify_inclusion(m, n, leaves[m], ref_mth(data), bad_dir) is False

            # Truncated proof must fail
            if actual_proof:
                trunc = copy.deepcopy(actual_proof)[:-1]
                assert rfc6962_verify_inclusion(m, n, leaves[m], ref_mth(data), trunc) is False

            # Extra step appended must fail
            extra = copy.deepcopy(actual_proof) + [{"position": "right", "hash": "00" * 32}]
            assert rfc6962_verify_inclusion(m, n, leaves[m], ref_mth(data), extra) is False


def test_witness_lifecycle_and_split_view_detection(keys):
    """Test witness key rotation, monotonic state rejection of forks, and split-view detection."""
    bl_priv, bl_pub = keys

    wit_priv = ed25519.Ed25519PrivateKey.generate()
    wit_priv_hex = wit_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    wit_pub_hex = wit_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    storage = MemoryWitnessStorage()
    witness = IndependentWitness(
        witness_id="wit_lifecycle",
        witness_key_id="wit_k1",
        witness_private_key_hex=wit_priv_hex,
        log_trust_roots={"bl_k": bl_pub},
        storage=storage,
    )

    # 1. First valid checkpoint at tree_size = 5
    cp1 = {
        "protocol_version": "checkpoint/1.0",
        "log_id": "monitored_log",
        "tree_size": 5,
        "root_hash": "11" * 32,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checkpoint_id": "cp_size_5",
        "previous_root_hash": None,
        "signing": {"signer_key_id": "bl_k", "algorithm": "ed25519"},
    }
    cp1_msg = canonical_encode({
        "protocol_version": cp1["protocol_version"],
        "log_id": cp1["log_id"],
        "tree_size": cp1["tree_size"],
        "root_hash": cp1["root_hash"].lower(),
        "timestamp": cp1["timestamp"],
        "checkpoint_id": cp1["checkpoint_id"],
        "previous_root_hash": cp1["previous_root_hash"],
        "signer_key_id": cp1["signing"]["signer_key_id"],
        "algorithm": cp1["signing"]["algorithm"],
    })
    cp1["signing"]["signature"] = bl_priv.sign(cp1_msg).hex()

    ack1 = witness.observe_checkpoint(cp1)
    assert ack1.signature != ""
    assert storage.get_state("monitored_log").tree_size == 5

    # 2. Re-observation of identical checkpoint is accepted
    ack_dup = witness.observe_checkpoint(cp1)
    assert isinstance(ack_dup, WitnessAcknowledgement)
    assert ack_dup.signature != ""

    # 3. Rollback attempt: checkpoint at smaller tree_size 4 must be rejected
    cp_rollback = copy.deepcopy(cp1)
    cp_rollback["tree_size"] = 4
    cp_rollback["checkpoint_id"] = "cp_size_4"
    cp_rollback_msg = canonical_encode({
        "protocol_version": cp_rollback["protocol_version"],
        "log_id": cp_rollback["log_id"],
        "tree_size": cp_rollback["tree_size"],
        "root_hash": cp_rollback["root_hash"].lower(),
        "timestamp": cp_rollback["timestamp"],
        "checkpoint_id": cp_rollback["checkpoint_id"],
        "previous_root_hash": cp_rollback["previous_root_hash"],
        "signer_key_id": cp_rollback["signing"]["signer_key_id"],
        "algorithm": cp_rollback["signing"]["algorithm"],
    })
    cp_rollback["signing"]["signature"] = bl_priv.sign(cp_rollback_msg).hex()
    nak_rollback = witness.observe_checkpoint(cp_rollback)
    assert nak_rollback.reason_code == "TREE_ROLLBACK"

    # 4. Split-view fork attempt: different root at same tree_size 5 must be rejected as FORK_DETECTED
    cp_fork = copy.deepcopy(cp1)
    cp_fork["root_hash"] = "22" * 32
    cp_fork["checkpoint_id"] = "cp_fork_5"
    cp_fork_msg = canonical_encode({
        "protocol_version": cp_fork["protocol_version"],
        "log_id": cp_fork["log_id"],
        "tree_size": cp_fork["tree_size"],
        "root_hash": cp_fork["root_hash"].lower(),
        "timestamp": cp_fork["timestamp"],
        "checkpoint_id": cp_fork["checkpoint_id"],
        "previous_root_hash": cp_fork["previous_root_hash"],
        "signer_key_id": cp_fork["signing"]["signer_key_id"],
        "algorithm": cp_fork["signing"]["algorithm"],
    })
    cp_fork["signing"]["signature"] = bl_priv.sign(cp_fork_msg).hex()
    nak_fork = witness.observe_checkpoint(cp_fork)
    assert nak_fork.reason_code == "FORK_DETECTED"


