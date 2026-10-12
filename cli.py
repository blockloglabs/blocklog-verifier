#!/usr/bin/env python3
"""
Blocklog Standalone Receipt & Transparency Verifier CLI

Independent tool for cryptographic verification of execution receipts,
checkpoints, witness acknowledgements, and counterparty attestations without backend API access.
"""
import argparse
import json
import sys
from pathlib import Path

from .core import (
    StandaloneReceiptVerifier,
    TrustRoot,
    verify_receipt_file,
)


def print_success(msg: str) -> None:
    print(f"\033[92m✓ {msg}\033[0m")


def print_error(msg: str) -> None:
    print(f"\033[91m✗ {msg}\033[0m")


def print_warning(msg: str) -> None:
    print(f"\033[93m⚠ {msg}\033[0m")


def print_info(msg: str) -> None:
    print(f"\033[94mℹ {msg}\033[0m")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m verifier",
        description="Verify Blocklog execution receipts and transparency commitments (Standalone Verifier)",
    )
    parser.add_argument("receipt_file", type=str, help="Path to receipt JSON file")
    parser.add_argument("--public-key", "-k", type=str, default=None, help="Ed25519 public key (hex or base64)")
    parser.add_argument("--key-id", type=str, default=None, help="Key ID if using trust-root lookup")
    parser.add_argument("--trust-root-file", type=str, default=None, help="JSON file containing trust roots")
    parser.add_argument("--witness-roots", type=str, default=None, help="JSON file mapping witness_key_id -> ed25519 public key hex")
    parser.add_argument("--counterparty-roots", type=str, default=None, help="JSON file mapping counterparty_id -> ed25519 public key hex")
    parser.add_argument("--allowed-witness-ids", type=str, nargs="*", default=None, help="Optional list of accepted witness IDs")
    parser.add_argument(
        "--no-signature",
        action="store_true",
        help="Perform structural and envelope validation only without verifying digital signatures. WARNING: Does not establish cryptographic authenticity.",
    )
    parser.add_argument("--require-merkle", action="store_true", help="Require valid Merkle inclusion proof")
    parser.add_argument("--json-output", "-j", action="store_true", help="Output machine-readable JSON result")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose details")

    args = parser.parse_args()

    trust_roots = {}
    if args.trust_root_file:
        try:
            with open(args.trust_root_file, "r", encoding="utf-8") as f:
                roots_data = json.load(f)
                for item in roots_data:
                    tr = TrustRoot(
                        key_id=item["key_id"],
                        public_key=item["public_key"],
                        status=item.get("status", "active"),
                        algorithm=item.get("algorithm", "ed25519"),
                    )
                    trust_roots[tr.key_id] = tr
        except Exception as exc:
            print_error(f"Failed to load trust roots: {exc}")
            sys.exit(2)

    witness_roots = {}
    if args.witness_roots:
        try:
            with open(args.witness_roots, "r", encoding="utf-8") as f:
                witness_roots = json.load(f)
        except Exception as exc:
            print_error(f"Failed to load witness roots: {exc}")
            sys.exit(2)

    counterparty_roots = {}
    if args.counterparty_roots:
        try:
            with open(args.counterparty_roots, "r", encoding="utf-8") as f:
                counterparty_roots = json.load(f)
        except Exception as exc:
            print_error(f"Failed to load counterparty roots: {exc}")
            sys.exit(2)

    verifier = StandaloneReceiptVerifier(
        trust_roots=trust_roots,
        default_public_key=args.public_key,
        witness_trust_roots=witness_roots,
        counterparty_trust_roots=counterparty_roots,
    )

    path = Path(args.receipt_file)
    if not path.exists():
        print_error(f"File not found: {args.receipt_file}")
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8") as f:
            receipt_data = json.load(f)

        result = verifier.verify(
            receipt_data,
            public_key_override=args.public_key,
            require_signature=not args.no_signature,
            require_merkle=args.require_merkle,
            allowed_witness_ids=args.allowed_witness_ids,
        )

        if args.json_output:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print()
            print("=" * 60)
            print("BLOCKLOG INDEPENDENT RECEIPT VERIFICATION")
            print("=" * 60)
            print()

            if result.verified and result.cryptographically_verified:
                print_success("VERIFICATION PASSED: Cryptographic integrity and signature confirmed")
            elif result.structural_valid and not result.signature_verified:
                print_warning("STRUCTURAL VALIDATION PASSED (Cryptographic signature was NOT verified)")
                print_warning("WARNING: Do NOT rely on this result for security, trust, or compliance decisions.")
            else:
                print_error("VERIFICATION FAILED: Inconsistencies or invalid signatures detected")

            if result.receipt_id:
                print_info(f"Receipt ID: {result.receipt_id}")
            print_info(f"Verified At: {result.verified_at}")

            if result.transparency_assessment:
                ta = result.transparency_assessment
                print_info(f"Transparency Status: {ta.get('status')} (Witness ACKs verified: {ta.get('witness_acks_verified')})")

            if result.outcome_assessment:
                oa = result.outcome_assessment
                print_info(f"Claimed Status: {oa.get('claimed_status')} (Source: {oa.get('source_type')})")
                print_info(f"Real-World Verified: {oa.get('real_world_verified')} (Confidence: {oa.get('confidence')})")

            print("\nVerification Checks:")
            for chk in result.checks:
                if chk.passed:
                    print_success(f"  [{chk.name}] {chk.detail}")
                else:
                    print_error(f"  [{chk.name}] {chk.detail}")

            if result.warnings:
                print("\nWarnings:")
                for w in result.warnings:
                    print_warning(f"  {w}")

            if result.errors:
                print("\nErrors:")
                for e in result.errors:
                    print_error(f"  {e}")

            print()
            print("=" * 60)

        sys.exit(0 if result.verified else 1)

    except Exception as exc:
        if args.json_output:
            print(json.dumps({"verified": False, "error": str(exc)}, indent=2))
        else:
            print_error(f"Execution error: {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()
