# AI Ecosystem Compatibility Results

- Started: 2026-07-05T05:32:33Z
- Finished: 2026-07-05T05:32:51Z
- Oath: oath 0.1.5
- Oath SHA-256: `22655ca0d324070fd38943e2bf339e813667d2c3496777656fb469eb632e9269`
- Overall: pass
- Minimum free-space guard: 1200 MiB

## Cases

- `core-ai-sdks`: pass in 5s, packages: `openai ai @ai-sdk/openai @ai-sdk/anthropic zod`
- `convex-cli-sdk`: pass in 4s, packages: `convex`
- `agent-protocol`: pass in 6s, packages: `@modelcontextprotocol/sdk @langchain/core`
- `ts-agent-tooling`: pass in 3s, packages: `typescript tsx @types/node`

## Disk Samples

```csv
timestamp,case,phase,available_mib
2026-07-05T05:32:33Z,core-ai-sdks,before,2615
2026-07-05T05:32:38Z,core-ai-sdks,after,2566
2026-07-05T05:32:38Z,convex-cli-sdk,before,2566
2026-07-05T05:32:42Z,convex-cli-sdk,after,2496
2026-07-05T05:32:42Z,agent-protocol,before,2496
2026-07-05T05:32:48Z,agent-protocol,after,2419
2026-07-05T05:32:48Z,ts-agent-tooling,before,2419
2026-07-05T05:32:51Z,ts-agent-tooling,after,2361
```

Full logs are saved under `compat-results/ai-ecosystem/20260705T053233Z/logs`.
