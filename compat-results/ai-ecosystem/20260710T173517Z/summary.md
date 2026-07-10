# AI Ecosystem Compatibility Results

- Started: 2026-07-10T17:35:17Z
- Finished: 2026-07-10T17:35:48Z
- Oath: oath 0.1.6
- Oath SHA-256: `8afc02a7b4c11bbd3be0b6718fc5773763edadbb05218ea51a2a3e1c9511a4e7`
- Overall: pass
- Minimum free-space guard: 1200 MiB

## Cases

- `core-ai-sdks`: pass in 5s, packages: `openai ai @ai-sdk/openai @ai-sdk/anthropic zod`
- `convex-cli-sdk`: pass in 4s, packages: `convex`
- `agent-protocol`: pass in 6s, packages: `@modelcontextprotocol/sdk @langchain/core`
- `ts-agent-tooling`: pass in 16s, packages: `typescript tsx @types/node`

## Disk Samples

```csv
timestamp,case,phase,available_mib
2026-07-10T17:35:17Z,core-ai-sdks,before,15200
2026-07-10T17:35:22Z,core-ai-sdks,after,15154
2026-07-10T17:35:22Z,convex-cli-sdk,before,15154
2026-07-10T17:35:26Z,convex-cli-sdk,after,15088
2026-07-10T17:35:26Z,agent-protocol,before,15088
2026-07-10T17:35:32Z,agent-protocol,after,15016
2026-07-10T17:35:32Z,ts-agent-tooling,before,15016
2026-07-10T17:35:48Z,ts-agent-tooling,after,14440
```

Full logs are saved under `compat-results/ai-ecosystem/20260710T173517Z/logs`.
