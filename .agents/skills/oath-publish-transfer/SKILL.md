---
name: oath-publish-transfer
description: Safely assess, package, transfer, stage, review, approve, or reject a JavaScript release with Oath and npm staged publishing. Use for package handoffs, agent-to-agent package transfer, release review, SBOM/provenance generation, and npm stage operations.
---

# Oath publish and transfer

Use the signed Oath assessment as release evidence and npm staged publishing as the registry approval mechanism. They solve different problems; neither is proof that code is harmless.

## Create a reviewable handoff

1. Build required artifacts without secrets in the package tree.
2. Run `oath publish --dry-run --json` and resolve any denial.
3. Run `oath transfer create --output oath-transfer --json`.
4. Send the complete capsule directory. Do not send only the tarball or only `transfer.json`.

The capsule contains the package tarball, signed assessment, SPDX SBOM, SLSA-shaped provenance statement, and a signed manifest binding their hashes. Packing disables lifecycle scripts, so generated artifacts must already exist.

## Receive a handoff

1. Obtain the sender's Ed25519 public key through a separate trusted channel.
2. Run `oath transfer verify <capsule> --trusted-public-key <base64> --json`.
3. Require `verified: true` and `signature_trusted: true`, but retain `consumer_decision: review-required`. Without a trusted key, Oath returns `abstain`.
4. Review the capability and previous-release diffs in `evidence/assessment.json`.
5. Inspect or unpack the tarball without executing lifecycle hooks.
6. Reassess and sandbox any package binary before running it.

## npm staged publishing

- Stage only after Oath preflight: `oath publish --stage`.
- Inspect with `oath stage list --json`, `oath stage view <id> --json`, and `oath stage download <id> --destination <dir> --json`.
- A human with npm 2FA approves or rejects. `oath stage approve <id> --yes` and `oath stage reject <id> --yes` are irreversible registry decisions.
- Never let an autonomous agent approve solely from a score, signature, SBOM, provenance, or transfer verification.

## Honest claims

Oath adds pre-publish secret/capability checks, signed evidence, previous-release diffs, and agent-readable abstention. npm staging supplies registry-side delayed visibility and proof-of-presence approval. npm provenance supplies public build identity when run in a supported trusted CI environment. State all three boundaries separately.
