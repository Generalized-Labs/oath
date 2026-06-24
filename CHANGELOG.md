# Changelog

All notable changes to oath are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

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
