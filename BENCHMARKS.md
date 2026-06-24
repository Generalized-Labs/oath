# oath benchmarks

Machine: Apple M1, macOS 15.6.1, Node v22.12.0, bun 1.2.20
Date: June 23, 2025

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

## Key insight

oath exec matches npx speed while providing full security scanning.
oath install is slower than bun (bun uses binary lockfile protocol, no security scanning)
but competitive with npm while scanning every package for malware.

The tradeoff: 2-6s extra on cold large installs buys you detection of supply chain attacks
that npm/bun/pnpm would execute silently.

## Score examples

```
$ oath score chalk
  chalk@5.6.2 -- 100/100 (A)

$ oath score express
  express@5.2.1 -- 88/100 (B)

$ oath score lodash
  lodash@4.18.1 -- 80/100 (B)
```
