# Contributing

Thanks for helping make oath safer and more reliable.

## Development

Requirements:

- Rust stable
- Node.js for package execution smoke tests
- `cargo-audit` for release checks: `cargo install cargo-audit --locked`

Common checks:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
scripts/launch-check.sh
```

Network-backed tests contact the npm registry. If you are changing resolver,
fetch, install, or exec behavior, run the full launch check before opening a PR.

## Pull Requests

Keep PRs focused. Include:

- the user-visible behavior change
- tests or smoke coverage for the changed path
- any security assumptions or compatibility tradeoffs

Do not commit local secrets, `.npmrc`, `.env*`, or `.gstack/` artifacts.

## Security Changes

For code that touches tarball extraction, package linking, script execution,
registry auth, installer checksums, or release workflows, include a short threat
model in the PR description.
