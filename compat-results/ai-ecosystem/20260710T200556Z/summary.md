# AI Ecosystem Compatibility Results

- Started: 2026-07-10T20:05:56Z
- Finished: 2026-07-10T20:06:31Z
- Oath: oath 0.1.7
- Oath SHA-256: `3acfc179d685d06cb60484be73e71b2788053c28d521c9f95a3c876fef4bfe6a`
- Overall: pass
- Minimum free-space guard: 1200 MiB

## Cases

- `core-ai-sdks`: pass in 8s, packages: `openai ai @ai-sdk/openai @ai-sdk/anthropic zod`
- `convex-cli-sdk`: pass in 7s, packages: `convex`
- `agent-protocol`: pass in 9s, packages: `@modelcontextprotocol/sdk @langchain/core`
- `ts-agent-tooling`: pass in 11s, packages: `typescript tsx @types/node`

## Disk Samples

```csv
timestamp,case,phase,available_mib
2026-07-10T20:05:56Z,core-ai-sdks,before,10183
2026-07-10T20:06:04Z,core-ai-sdks,after,10132
2026-07-10T20:06:04Z,convex-cli-sdk,before,10132
2026-07-10T20:06:11Z,convex-cli-sdk,after,10068
2026-07-10T20:06:11Z,agent-protocol,before,10068
2026-07-10T20:06:20Z,agent-protocol,after,9998
2026-07-10T20:06:20Z,ts-agent-tooling,before,9998
2026-07-10T20:06:31Z,ts-agent-tooling,after,9426
```

Full logs are saved under `compat-results/ai-ecosystem/20260710T200556Z/logs`.
