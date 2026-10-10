"""
RFC 6962 Merkle Tree, Inclusion Proof & Consistency Proof Primitives.

Zero-dependency standalone implementation.
Fully implements Section 2.1 of RFC 6962 (Certificate Transparency):
- 0x00 prefix for leaf hashes
- 0x01 prefix for internal node hashes
- Subtree partitioning at highest power of 2 less than n
- Inclusion proof generation and verification
- Consistency proof generation and verification
"""
from __future__ import annotations

import hashlib
from typing import List, Tuple, Union


def sha256_digest(data: bytes) -> bytes:
    """Compute 32-byte SHA-256 digest."""
    return hashlib.sha256(data).digest()


def rfc6962_leaf_hash(data: bytes | str) -> bytes:
    """
    Compute RFC 6962 leaf hash: SHA-256(0x00 || data).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return sha256_digest(b"\x00" + data)


def rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    """
    Compute RFC 6962 internal node hash: SHA-256(0x01 || left || right).
    """
    return sha256_digest(b"\x01" + left + right)


def _split_index(n: int) -> int:
    """Find the largest power of 2 less than n."""
    if n < 2:
        return 0
    # Bit-twiddling to find largest power of 2 strictly less than n
    return 1 << ((n - 1).bit_length() - 1)


def rfc6962_tree_hash(leaves: List[bytes]) -> bytes:
    """
    Compute RFC 6962 Merkle Tree Hash (MTH) for a list of leaf hashes.
    
    If leaves contains raw leaf data, caller should hash them with rfc6962_leaf_hash first.
    If leaves is empty, returns SHA-256("").
    """
    n = len(leaves)
    if n == 0:
        return sha256_digest(b"")
    if n == 1:
        return leaves[0]

    k = _split_index(n)
    left_mth = rfc6962_tree_hash(leaves[:k])
    right_mth = rfc6962_tree_hash(leaves[k:])
    return rfc6962_node_hash(left_mth, right_mth)


# ── Inclusion Proof Generation & Verification ────────────────────────────────

def _sub_inclusion_path(m: int, leaves: List[bytes]) -> List[Tuple[str, bytes]]:
    """Internal helper to construct inclusion proof path."""
    n = len(leaves)
    if n <= 1:
        return []

    k = _split_index(n)
    if m < k:
        right_hash = rfc6962_tree_hash(leaves[k:])
        return _sub_inclusion_path(m, leaves[:k]) + [("right", right_hash)]
    else:
        left_hash = rfc6962_tree_hash(leaves[:k])
        return _sub_inclusion_path(m - k, leaves[k:]) + [("left", left_hash)]


def rfc6962_inclusion_proof(leaf_index: int, leaves: List[bytes]) -> List[dict]:
    """
    Generate an RFC 6962 inclusion proof for leaf at leaf_index (0-indexed).
    Returns list of {'position': 'left'|'right', 'hash': hex_string}.
    """
    n = len(leaves)
    if leaf_index < 0 or leaf_index >= n:
        raise ValueError(f"Leaf index {leaf_index} out of bounds for tree size {n}")

    raw_path = _sub_inclusion_path(leaf_index, leaves)
    return [{"position": pos, "hash": h.hex()} for pos, h in raw_path]


def rfc6962_verify_inclusion(
    leaf_index: int,
    tree_size: int,
    leaf_hash: bytes | str,
    root_hash: bytes | str,
    proof: List[dict],
) -> bool:
    """
    Verify an RFC 6962 inclusion proof.
    """
    if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
        return False

    current = bytes.fromhex(leaf_hash) if isinstance(leaf_hash, str) else leaf_hash
    expected_root = bytes.fromhex(root_hash) if isinstance(root_hash, str) else root_hash

    if tree_size == 1:
        return len(proof) == 0 and current == expected_root

    # Compute expected RFC 6962 path directions for (leaf_index, tree_size)
    def _expected_directions(m: int, n: int) -> List[str]:
        if n <= 1:
            return []
        k = 1 << ((n - 1).bit_length() - 1)
        if m < k:
            return _expected_directions(m, k) + ["right"]
        else:
            return _expected_directions(m - k, n - k) + ["left"]

    expected_dirs = _expected_directions(leaf_index, tree_size)
    if len(proof) != len(expected_dirs):
        return False

    for idx, step in enumerate(proof):
        pos = step.get("position")
        h_str = step.get("hash")
        if not pos or not h_str or pos != expected_dirs[idx]:
            return False
        sib = bytes.fromhex(h_str)
        if pos == "right":
            current = rfc6962_node_hash(current, sib)
        elif pos == "left":
            current = rfc6962_node_hash(sib, current)
        else:
            return False

    return current == expected_root


# ── Consistency Proof Generation & Verification ──────────────────────────────

def _sub_consistency_proof(m: int, leaves: List[bytes], b: bool) -> List[bytes]:
    """RFC 6962 subproof implementation."""
    n = len(leaves)
    if m == n:
        if b:
            return []
        return [rfc6962_tree_hash(leaves)]

    k = _split_index(n)
    if m <= k:
        return _sub_consistency_proof(m, leaves[:k], b) + [rfc6962_tree_hash(leaves[k:])]
    else:
        return _sub_consistency_proof(m - k, leaves[k:], False) + [rfc6962_tree_hash(leaves[:k])]


def rfc6962_consistency_proof(m: int, leaves: List[bytes]) -> List[str]:
    """
    Generate RFC 6962 consistency proof showing that tree of size len(leaves)
    strictly extends previous tree of size m (1 <= m <= len(leaves)).
    Returns list of 64-character hex hash strings.
    """
    n = len(leaves)
    if m < 1 or m > n:
        raise ValueError(f"Invalid consistency proof bounds: m={m}, n={n} (require 1 <= m <= n)")
    if m == n:
        return []

    raw_nodes = _sub_consistency_proof(m, leaves, True)
    return [node.hex() for node in raw_nodes]


def rfc6962_verify_consistency(
    m: int,
    n: int,
    root_m: bytes | str,
    root_n: bytes | str,
    proof: List[bytes | str],
) -> bool:
    """
    Verify an RFC 6962 consistency proof between tree size m and n.
    
    Returns True if root_n is proven to be a valid append-only extension of root_m.
    """
    try:
        rm = bytes.fromhex(root_m) if isinstance(root_m, str) else root_m
        rn = bytes.fromhex(root_n) if isinstance(root_n, str) else root_n
    except ValueError:
        return False

    if m == n:
        return len(proof) == 0 and rm == rn
    if m < 1 or m >= n:
        return False
    if not proof:
        return False

    try:
        p_bytes = [bytes.fromhex(x) if isinstance(x, str) else x for x in proof]
    except ValueError:
        return False

    # Step 1: If m is a power of 2, node_m starts as rm; otherwise it is proof[0]
    if (m & (m - 1)) == 0:
        node_m = rm
        node_n = rm
        p = list(p_bytes)
    else:
        node_m = p_bytes[0]
        node_n = p_bytes[0]
        p = list(p_bytes[1:])

    fn = m - 1
    sn = n - 1

    # Step 2: Skip common prefix
    while (fn & 1) == 1:
        fn >>= 1
        sn >>= 1

    # Step 3: Traverse proof nodes
    for sibling in p:
        if sn == 0:
            return False

        if (fn & 1) == 1 or fn == sn:
            node_m = rfc6962_node_hash(sibling, node_m)
            node_n = rfc6962_node_hash(sibling, node_n)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            node_n = rfc6962_node_hash(node_n, sibling)

        fn >>= 1
        sn >>= 1

    # Step 4: Verify computed roots match expected roots
    return node_m == rm and node_n == rn and sn == 0
