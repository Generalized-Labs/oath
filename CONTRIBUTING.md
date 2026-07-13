# Contributing

Thanks for helping make oath safer and more reliable.

## Development

Requirements:

- Rust 1.94 or newer
- Node.js for package execution smoke tests
- `cargo-audit` for release checks: `cargo install cargo-audit --locked`

Common checks:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo test --workspace --locked
cargo audit --deny warnings
node scripts/validate-agent-skills.mjs
scripts/launch-check.sh
OATH_BIN=target/release/oath scripts/compat-ai-ecosystem.sh
(cd website && npm ci && npm audit && npm run build)
```

Network-backed tests contact the npm registry. If you are changing resolver,
fetch, install, or exec behavior, run the full launch check before opening a PR.
The AI ecosystem compatibility check is release-oriented and covers Convex,
Vercel AI SDK packages, OpenAI SDK, MCP SDK, LangChain core, and TypeScript/tsx
tooling while recording disk and timing metrics.

Before a release tag, manually dispatch the complete CI workflow on the exact
candidate commit. The `release-evidence-gate`, real-project aggregate, native
Linux and Windows security jobs, PostgreSQL registry test, reliability drill,
and dependency audit must all pass. A pull-request run alone does not execute
every release-evidence lane.

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
