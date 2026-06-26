# oath

A security-first replacement for **npm, npx, and bun** — it reads every dependency
for malicious behavior before a line runs. Faster. Safer. No surprises.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Generalized-Labs/oath/master/install.sh | sh
```

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
- **Transparency log** — every install appended to `~/.oath/transparency.log`
- **Faster** — 0.9s cold, 0.2s warm (abbreviated packuments, 5-min TTL cache, content-addressable store)
- **Full npm compatibility** — workspaces, git deps, global install, publish, lifecycle scripts

Detection is measured against a corpus of popular and real-malware packages — see the [scanner threat model](docs/scanner-threat-model.md) for the methodology, the false-positive/recall tradeoff, and honest limits. Speed numbers are in [BENCHMARKS.md](BENCHMARKS.md).

## Commands

```sh
oath install              # install from package.json
oath install express      # add + install
oath install -D typescript # add to devDependencies
oath install -g typescript # global install
oath add lodash            # add dependency
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

Scripts are blocked by default. Allowlist packages:
```json
{
  "trustedDependencies": ["esbuild", "prisma"]
}
```

Or allow all for a project:
```sh
oath install --run-scripts
```

## Requirements

- macOS (arm64, x64) or Linux (x64)
- Node.js (for running installed packages — oath itself needs none)

## License

MIT
