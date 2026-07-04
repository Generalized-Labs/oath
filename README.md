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
- **Fast warm installs** — lockfile and content-addressable store fast paths avoid unnecessary resolution and relinking
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
oath publish              # publish to npm registry
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

## Requirements

- macOS (arm64, x64) or Linux (x64)
- Node.js (for running installed packages — oath itself needs none)

## License

MIT
