# oath scanner: threat model & honest limits

oath statically analyzes every JavaScript/TypeScript file in a package (and its
install-script commands) and renders a tiered verdict. This document states what
that detection does and — just as importantly — what it does **not** do, with
measured numbers. It is deliberately not marketing copy.

## Detection model

The core principle (following the npm-malware research consensus): **a capability
is not a crime — a gated, correlated combination is.** Using `fs`, `http`,
`child_process`, `eval`, or `process.env` is normal; express, webpack, and prisma
all do. So capabilities are reported as **neutral facts**, and a package only
escalates to *warn* or *flag* when the AST shows a dangerous **combination**:

| Verdict | Trigger (examples) |
|---|---|
| **flag** | a base64/charcode decode **→** `eval`/`Function`/`require` (AST-nested); install hook + shell/decode-exec/C2/worm behavior; a known exfil/C2 host (Telegram/Discord/ngrok/oastify/file-drops) + network or credential access |
| **warn** | a sensitive-env name or credential-path string occurs with network access in the same file; reads secrets *and* spawns processes; other lower-confidence combinations |
| **ok** | capabilities present, no dangerous combination |

Detection is **AST-first** (oxc): code constructs are matched as syntax, so a
dangerous API mentioned in a comment or an example string cannot trigger a code
detection. Host/path/blob signatures run only over string-literal and
template-literal text, never raw source. The install-script command itself is
scanned, since many attacks put the entire payload in `preinstall`.

## Last published benchmark baseline

The following corpus numbers were measured on the v0.1.6 behavioral engine.
Later releases narrowed package-level correlation to same-file correlation, so
do not present these exact percentages as v0.2.0 measurements until the corpus
is rerun on the exact release candidate.

Benchmarked with `cargo run --release -p oath-analyze --example bench` against:
- **benign:** 1,776 package trees from a local store of the most-depended-on npm
  packages (bundled/vendored sub-packages counted separately).
- **malware:** 883 real npm samples from DataDog's labeled
  `malicious-software-packages-dataset` (static analysis only — never executed).

| | substring engine (old) | behavioral engine (current) |
|---|---|---|
| **false-positive rate** (benign flagged) | 11.6% | **0.6%** |
| **recall** (malware caught) | 42.3% | **57.5%** |

The low-false-positive operating point is intentional: false alarms on the
packages everyone installs destroy trust. The exfil rule treats a *specifically*
sensitive source — a credential-shaped env var (`AWS_SECRET`, `NPM_TOKEN`, …) or
a credential-file path (`~/.ssh/id_rsa`, `.aws/credentials`) — occurring with
network access as reviewable, not automatically malicious. It escalates to a
block only with stronger corroboration such as a known exfiltration host. A build
tool merely capturing the whole environment (vite/webpack `define`, `loadEnv`) is
**not** flagged.

## What it does NOT catch (honest limits)

The published baseline missed **42.5% of the malware corpus**. The exact current
miss rate is unknown until the corpus is rerun, and substantial misses are
expected for a JavaScript static analyzer. They fall into classes that are out
of scope or inherently hard:

- **Binary-payload droppers.** Packages whose malice lives in a bundled `.exe` /
  `.node` / native binary (e.g. fake `*-win32-x64` packages). A JS scanner sees
  only a tiny wrapper.
- **Remotely-fetched second-stage payloads.** If the package only *downloads* and
  runs code at install time, the malicious code is on an attacker's server, not
  in the published files. The download mechanism may be flagged; the payload is
  unobservable statically.
- **Subtle compromised-library injections.** A few lines added to an otherwise
  legitimate, large package — low signal-to-noise for any static heuristic.
- **Pure-metadata attacks** (typosquats with empty/benign code, manifest
  confusion). These need registry/metadata/reputation signals, not code analysis.

## What this means in practice

oath's scanner is a **high-signal, low-noise first-pass filter**, not a guarantee
of safety. It is strongest at the dominant real-world npm attack shapes
(install-hook payloads, env/credential exfiltration, decode-then-execute, C2 to
known sinks) and is honest about everything else. It complements — does not
replace — registry reputation, lockfile pinning, the `--min-age` cooldown, and
running install scripts only for trusted packages.

These historical numbers do not meet Oath's GA detection contract of at least
98% known-malware recall, at least 95% private-adversarial recall, and at most
0.5% false positives. The CLI may ship as a developer preview with this limit;
the scanner must not be marketed as GA-grade malware detection.

## Reproduce

```sh
# benign corpus = your local store of installed popular packages
cargo run --release -p oath-analyze --example bench -- ~/.oath/store <malware_dir>
```
The malware corpus (DataDog, Apache-2.0) is cloned separately and extracted
read-only; nothing in it is ever executed.
