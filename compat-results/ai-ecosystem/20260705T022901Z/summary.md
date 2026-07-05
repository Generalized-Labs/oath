# AI Ecosystem Compatibility Results

- Started: 2026-07-05T02:29:01Z
- Finished: 2026-07-05T02:29:18Z
- Oath: oath 0.1.4
- Oath SHA-256: `430c5da477fde3097e52330035caf95912914f966f15d13b758d5f325ed9c492`
- Overall: fail
- Minimum free-space guard: 1200 MiB

## Cases

- `core-ai-sdks`: pass in 5s, packages: `openai ai @ai-sdk/openai @ai-sdk/anthropic zod`
- `convex-cli-sdk`: pass in 4s, packages: `convex`
- `agent-protocol`: fail in 5s, packages: `@modelcontextprotocol/sdk @langchain/core`
- `ts-agent-tooling`: pass in 3s, packages: `typescript tsx @types/node`

## Disk Samples

```csv
timestamp,case,phase,available_mib
2026-07-05T02:29:01Z,core-ai-sdks,before,3628
2026-07-05T02:29:06Z,core-ai-sdks,after,3566
2026-07-05T02:29:06Z,convex-cli-sdk,before,3566
2026-07-05T02:29:10Z,convex-cli-sdk,after,3496
2026-07-05T02:29:10Z,agent-protocol,before,3496
2026-07-05T02:29:15Z,agent-protocol,after,3413
2026-07-05T02:29:15Z,ts-agent-tooling,before,3412
2026-07-05T02:29:18Z,ts-agent-tooling,after,3361
```

Full logs are saved under `compat-results/ai-ecosystem/20260705T022901Z/logs`.
