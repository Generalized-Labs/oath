# AI Ecosystem Compatibility Results

- Started: 2026-07-06T03:40:12Z
- Finished: 2026-07-06T03:41:11Z
- Oath: oath 0.1.6
- Oath SHA-256: `ba1195c5ab42cb303470fb3d09e08c19cbba2759a221f2faf64cbdc70bc9180e`
- Overall: pass
- Minimum free-space guard: 1200 MiB

## Cases

- `core-ai-sdks`: pass in 10s, packages: `openai ai @ai-sdk/openai @ai-sdk/anthropic zod`
- `convex-cli-sdk`: pass in 17s, packages: `convex`
- `agent-protocol`: pass in 19s, packages: `@modelcontextprotocol/sdk @langchain/core`
- `ts-agent-tooling`: pass in 13s, packages: `typescript tsx @types/node`

## Disk Samples

```csv
timestamp,case,phase,available_mib
2026-07-06T03:40:12Z,core-ai-sdks,before,9434
2026-07-06T03:40:22Z,core-ai-sdks,after,9365
2026-07-06T03:40:22Z,convex-cli-sdk,before,9365
2026-07-06T03:40:39Z,convex-cli-sdk,after,9283
2026-07-06T03:40:39Z,agent-protocol,before,9283
2026-07-06T03:40:58Z,agent-protocol,after,9217
2026-07-06T03:40:58Z,ts-agent-tooling,before,9217
2026-07-06T03:41:11Z,ts-agent-tooling,after,9164
```

Full logs are saved under `compat-results/ai-ecosystem/20260706T034012Z/logs`.
