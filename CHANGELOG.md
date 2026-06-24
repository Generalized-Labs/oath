# Changelog

All notable changes to oath are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [0.1.3] - 2026-06-24

### Added
- **`oath exec` always-on pre-run card.** Before running a package, oath now shows
  its safety grade + score, publish age, last publisher, open-source flag,
  readable-vs-obfuscated, unpacked size, and runtime permissions — replacing
  npm/npx's uninformative `[y/N]` prompt with a real verdict.
- **`oath exec --json`** emits a machine-readable verdict (`grade`, `score`,
  `capabilities`, `last_publisher`, `age_days`, `integrity`, `decision`, …) so an
  AI agent or CI step can vet a `skill.md` / `npx`-style command *before* it runs —
  closing a real supply-chain hole for agents.
- **Agent gates**: `oath exec --require-grade <A-F>` and `--dry-run`, with stable
  exit codes an agent can branch on without parsing text: `10` blocked by grade,
  `11` blocked by min-age, `13` declined.

## [0.1.2] - 2026-06-24

### Added
- `oath run` and install scripts now export the `npm_*` lifecycle env vars
  (`npm_lifecycle_event`, `npm_package_name`, `npm_package_version`, and the
  flattened `npm_package_<field>` set) that many build scripts rely on.
- Root project lifecycle hooks: a plain `oath install` now runs the project's
  own `preinstall`/`postinstall`/`prepare` scripts (e.g. husky), matching npm/bun.
  These are your own trusted scripts and always run, unlike blocked dependency
  scripts.
- Drop-in aliases: `oath ci` (clean install from the lockfile), `oath uninstall`
  / `oath rm` (= remove), and `oath x` (= exec).

### Changed
- `oath audit` is now `oath scan` (`audit` kept as an alias). It is behavioral
  analysis, not a CVE/advisory lookup, and the new name says so.
- Faster installs: package scanning now runs in parallel across CPU cores (the
  cold-install hot path), and a re-install with an unchanged lockfile skips the
  node_modules rebuild instead of nuking and relinking every time.

## [0.1.1] - 2026-06-24

### Removed
- `oathx` stub binary and the `oath exec --allow-read/--allow-write/--allow-env`
  flags, plus the install-script "sandbox" prompt option. None of these enforced
  anything — advertising enforcement a security tool does not have is worse than
  omitting it. OS-level sandboxing (macOS Seatbelt / Linux Landlock) is tracked
  for a later release.

### Added
- CI workflow running `cargo fmt --check`, `cargo clippy -D warnings`, and
  `cargo test` on every push to `master` and every pull request.
- `oath exec --yes` / `-y` to skip the risk prompt without prompting (replaces
  the misleadingly-named `--allow-net`, which only suppressed the prompt).

### Changed
- Scanner rebuilt AST-first (oxc): false-positive rate 11.6% → 1.1%, recall
  42.3% → 54.1% measured against 928 popular packages + 313 real npm-malware
  samples. See `docs/scanner-threat-model.md` for methodology and honest limits.
- Install scripts are blocked by default; allowlist via `trustedDependencies` or
  the policy file.
- `--min-age` release cooldown is now enforced on install (was previously dead).
- TLS switched to rustls so Linux cross-compiles need no system OpenSSL.
- README install command points at a working installer URL; `BENCHMARKS.md`
  score examples corrected to measured values (express 88/B, lodash 80/B).

### Fixed
- Private/scoped registry support via `.npmrc`.
- `package-lock.json` import for zero-friction migration.
- Install-time malware scan was skipped for every package (wrong store path).
- `oath verify` checked 0 packages (name read from the wrong field).

## [0.1.0]

- Initial release: security-first npm/npx replacement with static analysis,
  safety scoring, content-addressable store, transparency log, and multi-platform
  prebuilt binaries.
