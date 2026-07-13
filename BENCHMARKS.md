# oath benchmarks

Machine: Apple M1, macOS 15.6.1, Node v22.12.0, bun 1.2.20
Date: June 23, 2025

These are historical v0.1.x measurements, kept to show methodology and rough
shape. Refresh this file on the release machine before publishing a new public
release, especially after resolver, lockfile, linker, scanner, or release-profile
changes.

Current release checklist:

```sh
cargo build --release --locked --bin oath
scripts/launch-check.sh
```

## v0.2.0 release-candidate snapshot

The current checked-in benchmark was recorded on `darwin-arm64` with Node
v26.0.0, npm 11.12.1, and Bun 1.2.20. All installers used the same five-package
manifest with lifecycle scripts disabled and isolated cold caches.

| Installer | Cold | Warm |
|---|---:|---:|
| npm | 728 ms | 428 ms |
| Bun | 406 ms | 23 ms |
| Oath | 2,683 ms | 1,243 ms |

This sample does not support a speed claim: Oath was slower than npm and Bun.
The raw timings, versions, methodology, exit status, and normalized tree hashes
are in [`compat-results/benchmarks/installers.json`](compat-results/benchmarks/installers.json).

## Install (cold -- empty cache, no lockfile)

| Project Size | npm | bun | oath | oath overhead |
|---|---|---|---|---|
| Small (3 deps) | 1.78s | 0.23s | 0.22s | scans 3 packages |
| Medium (93 pkgs) | 3.12s | 0.72s | 2.35s | scans 7 new packages |
| Large (163 pkgs) | 5.43s | 1.08s | 8.60s | scans 69 new packages |

## Install (warm -- cached packages, lockfile exists, no node_modules)

| Project Size | npm | bun | oath |
|---|---|---|---|
| Small (3 deps) | 1.13s | 0.03s | 0.08s |
| Medium (93 pkgs) | ~1.5s | ~0.1s | 1.72s |
| Large (163 pkgs) | ~2.0s | ~0.2s | 3.62s |

## Package execution (oath exec vs npx)

| Scenario | npx | oath exec | Notes |
|---|---|---|---|
| Cold (cowsay) | 2.67s | 2.44s | oath fetches, resolves, scans, then runs |
| Warm (cached) | 2.23s | 2.24s | oath still scans before running |

## What oath does that others don't

Every install and exec includes:
- Static analysis of all JS/TS source files
- Detection of 14 malicious patterns (exfiltration, crypto mining, credential harvest, etc.)
- Capability mapping (network, fs, env, subprocess, dynamic eval)
- Permission prompt before execution
- Safety score computation (0-100, grade A-F)

## Interpretation

In this snapshot, `oath exec` was close to `npx` while adding pre-run scanning.
`oath install` was slower than bun on larger cold installs because oath scans
packages and bun uses a binary lockfile protocol.

The intended tradeoff is extra cold-install work in exchange for detection of
supply-chain attacks that npm/bun/pnpm would otherwise execute silently.

## Score examples

```
$ oath score chalk
  chalk@5.6.2 -- 100/100 (A)

$ oath score express
  express@5.2.1 -- 88/100 (B)

$ oath score lodash
  lodash@4.17.21 -- 80/100 (B)
```
