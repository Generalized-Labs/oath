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
`compat-results/ai-ecosystem/20260705T023030Z/summary.md`:

- Oath: `oath 0.1.4`
- Oath SHA-256: `430c5da477fde3097e52330035caf95912914f966f15d13b758d5f325ed9c492`
- Overall: pass
- Durations: 4s core AI SDKs, 4s Convex, 5s MCP/LangChain, 3s TS tooling
- Disk samples: 3552 MiB before the first case, 3303 MiB after the final case,
  with temp cleanup restoring the working volume to about 3.4 GiB free

## Notes

`@modelcontextprotocol/sdk@1.29.0` advertises a root export that points at
`dist/esm/index.js`, but that file is not present in the npm tarball. The smoke
test therefore validates the package through its real `client` and `server`
subpath exports, which is the meaningful compatibility check for Oath.
