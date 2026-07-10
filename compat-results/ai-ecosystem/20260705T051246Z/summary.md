# AI Ecosystem Compatibility Results

- Started: 2026-07-05T05:12:46Z
- Finished: 2026-07-05T05:13:07Z
- Oath: oath 0.1.4
- Oath SHA-256: `fb2ccd6b6409cf7d11864dc124922064c3fb64415654ded01b035317f14b48ef`
- Overall: pass
- Minimum free-space guard: 1200 MiB

## Cases

- `core-ai-sdks`: pass in 5s, packages: `openai ai @ai-sdk/openai @ai-sdk/anthropic zod`
- `convex-cli-sdk`: pass in 6s, packages: `convex`
- `agent-protocol`: pass in 7s, packages: `@modelcontextprotocol/sdk @langchain/core`
- `ts-agent-tooling`: pass in 3s, packages: `typescript tsx @types/node`

## Disk Samples

```csv
timestamp,case,phase,available_mib
2026-07-05T05:12:46Z,core-ai-sdks,before,1841
2026-07-05T05:12:51Z,core-ai-sdks,after,1802
2026-07-05T05:12:51Z,convex-cli-sdk,before,1802
2026-07-05T05:12:57Z,convex-cli-sdk,after,1730
2026-07-05T05:12:57Z,agent-protocol,before,1730
2026-07-05T05:13:04Z,agent-protocol,after,1657
2026-07-05T05:13:04Z,ts-agent-tooling,before,1657
2026-07-05T05:13:07Z,ts-agent-tooling,after,1598
```

Full logs are saved under `compat-results/ai-ecosystem/20260705T051246Z/logs`.
