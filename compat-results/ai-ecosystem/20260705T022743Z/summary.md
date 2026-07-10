# AI Ecosystem Compatibility Results

- Started: 2026-07-05T02:27:43Z
- Finished: 2026-07-05T02:28:01Z
- Oath: oath 0.1.4
- Oath SHA-256: `430c5da477fde3097e52330035caf95912914f966f15d13b758d5f325ed9c492`
- Overall: pass
- Minimum free-space guard: 1200 MiB

## Cases

- `core-ai-sdks`: pass in 4s, packages: `openai ai @ai-sdk/openai @ai-sdk/anthropic zod`
- `convex-cli-sdk`: pass in 4s, packages: `convex`
- `agent-protocol`: pass in 7s, packages: `@modelcontextprotocol/sdk @langchain/core`
- `ts-agent-tooling`: pass in 3s, packages: `typescript tsx @types/node`

## Disk Samples

```csv
timestamp,case,phase,available_mib
2026-07-05T02:27:43Z,core-ai-sdks,before,3750
2026-07-05T02:27:47Z,core-ai-sdks,after,3629
2026-07-05T02:27:47Z,convex-cli-sdk,before,3629
2026-07-05T02:27:51Z,convex-cli-sdk,after,3565
2026-07-05T02:27:51Z,agent-protocol,before,3565
2026-07-05T02:27:58Z,agent-protocol,after,3475
2026-07-05T02:27:58Z,ts-agent-tooling,before,3475
2026-07-05T02:28:01Z,ts-agent-tooling,after,3426
```

Full logs are saved under `compat-results/ai-ecosystem/20260705T022743Z/logs`.
