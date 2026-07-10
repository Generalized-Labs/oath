# AI Ecosystem Compatibility Results

- Started: 2026-07-05T02:30:30Z
- Finished: 2026-07-05T02:30:46Z
- Oath: oath 0.1.4
- Oath SHA-256: `430c5da477fde3097e52330035caf95912914f966f15d13b758d5f325ed9c492`
- Overall: pass
- Minimum free-space guard: 1200 MiB

## Cases

- `core-ai-sdks`: pass in 4s, packages: `openai ai @ai-sdk/openai @ai-sdk/anthropic zod`
- `convex-cli-sdk`: pass in 4s, packages: `convex`
- `agent-protocol`: pass in 5s, packages: `@modelcontextprotocol/sdk @langchain/core`
- `ts-agent-tooling`: pass in 3s, packages: `typescript tsx @types/node`

## Disk Samples

```csv
timestamp,case,phase,available_mib
2026-07-05T02:30:30Z,core-ai-sdks,before,3552
2026-07-05T02:30:34Z,core-ai-sdks,after,3494
2026-07-05T02:30:34Z,convex-cli-sdk,before,3494
2026-07-05T02:30:38Z,convex-cli-sdk,after,3420
2026-07-05T02:30:38Z,agent-protocol,before,3420
2026-07-05T02:30:43Z,agent-protocol,after,3358
2026-07-05T02:30:43Z,ts-agent-tooling,before,3358
2026-07-05T02:30:46Z,ts-agent-tooling,after,3303
```

Full logs are saved under `compat-results/ai-ecosystem/20260705T023030Z/logs`.
