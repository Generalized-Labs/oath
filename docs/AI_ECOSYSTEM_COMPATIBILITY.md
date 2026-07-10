# AI Ecosystem Compatibility

`scripts/compat-ai-ecosystem.sh` is a release-oriented npm compatibility smoke
test for packages that AI app developers and agents are likely to hit early.

The script creates isolated temp projects, runs `oath install --yes`, validates
runtime imports or bins, records disk samples and durations, snapshots the
manifest/lockfile outputs, then cleans the temp package store. Bulky logs stay
local under `compat-results/ai-ecosystem/<timestamp>/logs/`.

## Cases

- `core-ai-sdks`: `openai`, `ai`, `@ai-sdk/openai`, `@ai-sdk/anthropic`, `zod`
- `convex-cli-sdk`: `convex`
- `agent-protocol`: `@modelcontextprotocol/sdk`, `@langchain/core`
- `ts-agent-tooling`: `typescript`, `tsx`, `@types/node`, plus `oath exec --dry-run --json tsx`

## Running

```sh
cargo build --release --locked --bin oath
OATH_BIN=target/release/oath scripts/compat-ai-ecosystem.sh
```

The default free-space guard is `1200` MiB. Override it with
`MIN_FREE_MIB=<mib>` when running on larger CI machines.

## Latest Local Result

The latest local pass was recorded at
`compat-results/ai-ecosystem/20260710T173517Z/summary.md`:

- Oath: `oath 0.1.6`
- Oath SHA-256: `8afc02a7b4c11bbd3be0b6718fc5773763edadbb05218ea51a2a3e1c9511a4e7`
- Overall: pass
- Durations: 5s core AI SDKs, 4s Convex, 6s MCP/LangChain, 16s TS tooling
- Disk samples: 15200 MiB before the first case and 14440 MiB after the final
  case, with the working volume showing about 14 GiB free after the run

A prior local run at `20260706T033752Z` exposed tarball body timeouts on larger
AI ecosystem packages. Oath now gives tarball body downloads a longer timeout,
uses bounded retry/backoff for transient metadata and tarball failures, and
restarts interrupted tarball bodies from byte zero.

## Notes

`@modelcontextprotocol/sdk@1.29.0` advertises a root export that points at
`dist/esm/index.js`, but that file is not present in the npm tarball. The smoke
test therefore validates the package through its real `client` and `server`
subpath exports, which is the meaningful compatibility check for Oath.
