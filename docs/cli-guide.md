# Blocklog Verifier CLI Reference Guide

The `blocklog-verify` command-line utility enables standalone offline verification of execution receipts, transparency checkpoints, and witness attestations.

---

## 1. Syntax

```bash
blocklog-verify [OPTIONS] <receipt_file>
# Or:
python -m verifier [OPTIONS] <receipt_file>
```

---

## 2. Options and Arguments

### Positional Arguments
- `receipt_file`: Path to the receipt JSON document to verify.

### Key Resolution Options
- `-k, --public-key <HEX_OR_BASE64>`: Direct Ed25519 public key. Bypasses key ID lookups.
- `--key-id <KEY_ID>`: Expected key identifier to match in trust roots.
- `--trust-root-file <PATH>`: JSON file containing Blocklog signing keys.
- `--witness-roots <PATH>`: JSON file containing witness public keys (`{"witness_key_id": "public_key_hex"}`).
- `--counterparty-roots <PATH>`: JSON file containing external counterparty public keys (`{"counterparty_key_id": "public_key_hex"}`).

### Verification Flags
- `--require-merkle`: Fail verification if the receipt does not include a valid Merkle inclusion proof.
- `--no-signature`: Skip digital signature check (performs envelope syntax, canonical hash, and commitment checks only). **WARNING**: Does not establish cryptographic authenticity.
- `-j, --json-output`: Emit machine-readable JSON output instead of terminal formatting.
- `-v, --verbose`: Emit comprehensive human-readable check breakdowns.

---

## 3. Exit Codes

| Exit Code | Meaning | Action Required |
|---|---|---|
| `0` | **Verification Succeeded** | Receipt structure (and signatures, unless `--no-signature` specified) is valid. |
| `1` | **Verification Failed** | Tampering, signature mismatch, key revocation, or Merkle proof failure detected. |
| `2` | **Execution / Config Error** | Missing file, malformed JSON, or invalid arguments. |

---

## 4. Common Recipes

### Recipe 1: Strict CI/CD Pipeline Verification
```bash
if blocklog-verify receipt.json \
     --trust-root-file /etc/blocklog/trust_roots.json \
     --require-merkle; then
  echo "Audit passed"
else
  echo "SECURITY ALERT: Corrupted execution receipt" >&2
  exit 1
fi
```

### Recipe 2: Automated JSON Ingestion
```bash
python -m verifier receipt.json \
  --trust-root-file trust_roots.json \
  --json-output | jq '.transparency_assessment.status'
# Outputs: "WITNESSED"
```

### Recipe 3: Checking Counterparty Outcome
```bash
python -m verifier receipt.json \
  --trust-root-file trust_roots.json \
  --counterparty-roots counterparty_roots.json \
  --json-output | jq '.outcome_assessment.confidence'
# Outputs: "MAXIMAL"
```

---

## 5. Security Warning: The `--no-signature` Mode

The `--no-signature` flag is provided strictly for **offline schema inspection, debugging, and linting** of receipts before signing keys are distributed.

> [!CAUTION]
> Disabling signature verification means anyone could have created or altered the receipt document.
> - Automated systems MUST check the `cryptographically_verified` boolean in JSON output. When `--no-signature` is used, `cryptographically_verified` is always `false`.
> - Human-readable output will print a visible warning banner: `STRUCTURAL VALIDATION PASSED (Cryptographic signature was NOT verified)`.
> - Do NOT use `--no-signature` for authorization decisions, audit sign-offs, regulatory reporting, or transaction settlement.
