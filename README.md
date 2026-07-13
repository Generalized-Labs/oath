# oath

A security-first replacement for **npm install** and **npx** workflows. oath
checks packages for malicious behavior before third-party code runs, blocks
dependency install scripts by default, and records installs in a local
transparency log.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Generalized-Labs/oath/master/install.sh | sh
```

The installer downloads the latest GitHub Release binary and verifies the
matching `.sha256` sidecar before installing. If a release is missing checksums,
installation fails closed.

Or via Homebrew:
```sh
brew install generalized-labs/tap/oath
```

Or from source (Rust 1.85+):
```sh
git clone https://github.com/Generalized-Labs/oath && cd oath
cargo build --release        # binary at target/release/oath
cargo test --workspace       # run the test suite
```

## Why oath

- **Script blocking by default** — postinstall scripts only run for packages you trust
- **Behavioral analysis** — detects decode→exec payloads, env/secret exfiltration, install-script payloads at install time
- **Trusts what's proven** — a package with 1M+ weekly downloads and no critical finding grades A, so household tools (prettier, react, lodash) aren't false-flagged; real supply-chain attacks still surface as critical decode→exec/exfil and are blocked
- **Transparency log** — installs are appended to `~/.oath/transparency.log`
- **Verified package store** — cached packages carry a manifest with lock integrity, package identity, byte counts, and a deterministic BLAKE3 file tree
- **Bounded tarball unpacking** — tarballs are streamed to disk, size-limited, path-checked, and restricted to regular files/directories
- **Fast warm installs** — lockfile and verified-store fast paths avoid unnecessary resolution and relinking
- **npm compatibility where it matters first** — package.json deps/devDeps, npm aliases, scoped packages, git deps, workspaces, global installs, lifecycle scripts, and publish support are implemented; edge-case compatibility gaps should be reported

Detection is measured against a corpus of popular and real-malware packages —
see the [scanner threat model](docs/scanner-threat-model.md) for the methodology,
the false-positive/recall tradeoff, and honest limits. Performance notes are in
[BENCHMARKS.md](BENCHMARKS.md).

## Commands

```sh
oath install              # install from package.json
oath install express      # add + install
oath install -D typescript # add to devDependencies
oath ci                   # clean install from oath-lock.json
oath install --frozen-lockfile # fail if package.json and lockfile disagree
oath install -g typescript # global install
oath add lodash            # add dependency and install
oath remove lodash         # remove dependency
oath run build            # run script with pre/post hooks
oath exec prettier .      # run package binary (npx replacement)
oath exec --dry-run --json tsx # inspect identity, integrity, capabilities, and policy
oath exec --sandbox-mode native tsx # require native OS containment
oath publish --dry-run --json # inspect the exact npm packlist and release evidence
oath publish --stage      # assess, sign, and submit through npm staged publishing
oath stage list --json    # inspect npm staged releases (npm 11.15+)
oath transfer create --output oath-transfer --json # signed agent-to-agent handoff
oath transfer verify oath-transfer --trusted-public-key <base64> --json # verify assets and signer
oath log                  # view transparency log
oath score <pkg>          # security score for a package
```

## Workspaces

oath detects monorepos automatically:
```sh
oath install  # from workspace root — installs all packages, hoists shared deps
```

## Trusted Scripts

Third-party dependency install scripts are blocked by default. Allowlist packages:
```json
{
  "trustedDependencies": ["esbuild", "prisma"]
}
```

Or allow all for a project:
```sh
oath install --run-scripts
```

Project-owned lifecycle scripts such as root `preinstall`, `postinstall`, and
`prepare` run for plain `oath install`, matching npm-style project behavior.

## Lockfiles and CI

`oath-lock.json` records resolved packages, direct root dependencies, and the
root graph. `oath install` rewrites it when package.json changes. `oath ci`
requires package.json and the lockfile to match, removes stale `node_modules`,
links from the lockfile graph, and never rewrites the lockfile.

Use this in CI:

```sh
oath ci
oath verify
```

## Store Verification

Each package in `~/.oath/store` includes `.oath-store-manifest.json`. `oath`
checks that manifest before warm installs, `ci`, `verify`, `exec`, `score`, and
global installs. Old cache entries without a manifest are treated as unverified
and rebuilt from the registry.

`oath verify` now performs full manifest/tree verification and fails on missing,
tampered, malformed, or package.json-mismatched store entries.

Tarball safety limits default to 512 MiB compressed, 2 GiB unpacked, and 200k
entries. Emergency compatibility overrides are available:

```sh
OATH_MAX_TARBALL_BYTES=1073741824 oath install
OATH_MAX_UNPACKED_BYTES=4294967296 oath install
OATH_MAX_TARBALL_ENTRIES=400000 oath install
```

## Exec Sandboxing

`oath exec` remains unsandboxed by default for human npx compatibility in this
release. For agents or high-risk workflows:

```sh
oath exec --sandbox <pkg> -- <args>
oath exec --sandbox-mode node <pkg>
OATH_AGENT_MODE=1 oath exec <pkg>
```

`node` mode uses Node's permission flags when supported, allowing reads from the
project, temp exec tree, and temp dir, and writes to the project and temp dir.
Subprocesses, workers, addons, and network stay denied unless Node changes its
permission defaults. `native` mode fails closed unless its complete backend
probe succeeds. Strict Linux mode requires bubblewrap namespaces, Landlock ABI
V6 (kernel 6.12+), seccomp, `no_new_privs`, and resource limits. Windows uses a
per-execution restricted token, unique AppContainer profile, ACL-scoped writable
roots, and Job Object limits. macOS remains Node-permission-only; Oath does not
present that as Linux- or Windows-equivalent containment.

Approvals bind package identity, integrity, capabilities, and sandbox policy. A
new tarball hash always requires a new assessment and decision.

## Publishing and package transfer

`oath publish` uses npm's actual `npm pack --dry-run --json --ignore-scripts`
file list as the authoritative assessment input. It records file and capability
diffs from the previous Oath assessment and persists a signed assessment, SPDX
SBOM, and SLSA-shaped provenance statement before publication. These artifacts
do not prove that a package is safe.

For registry-side review, npm 11.15+ and Node 22.14+ users can stage with
`oath publish --stage`, then list, view, download, approve, or reject through
`oath stage`. Approval and rejection require explicit `--yes` confirmation and
npm proof-of-presence. For an offline or agent-to-agent handoff, `oath transfer`
creates a signed capsule binding the tarball and evidence hashes. The receiver
must supply the expected Ed25519 key from a separate trusted channel. Without
that trust anchor, verification returns `abstain`; with it, verification still
returns `review-required`. Execute transferred code only after a fresh Oath
assessment and an appropriate sandbox decision.

## Requirements

- macOS (arm64, x64), Linux (x64), or Windows (x64, arm64)
- Linux kernel 6.12+ and bubblewrap for strict native containment
- Node.js (for running installed packages — oath itself needs none)

## License

MIT
