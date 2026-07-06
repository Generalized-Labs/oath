# AI Ecosystem Compatibility Results

- Started: 2026-07-06T03:37:52Z
- Finished: 2026-07-06T03:38:37Z
- Oath: oath 0.1.6
- Oath SHA-256: `788ad41645aba234eec1c08e53512ae4581cff1b8853539083d83c7c1a11e5a1`
- Overall: fail
- Minimum free-space guard: 1200 MiB

## Cases

- `core-ai-sdks`: pass in 9s, packages: `openai ai @ai-sdk/openai @ai-sdk/anthropic zod`
- `convex-cli-sdk`: fail in 11s, packages: `convex`
- `agent-protocol`: fail in 12s, packages: `@modelcontextprotocol/sdk @langchain/core`
- `ts-agent-tooling`: pass in 12s, packages: `typescript tsx @types/node`

## Disk Samples

```csv
timestamp,case,phase,available_mib
2026-07-06T03:37:52Z,core-ai-sdks,before,9839
2026-07-06T03:38:01Z,core-ai-sdks,after,9792
2026-07-06T03:38:01Z,convex-cli-sdk,before,9792
2026-07-06T03:38:13Z,convex-cli-sdk,after,9764
2026-07-06T03:38:13Z,agent-protocol,before,9764
2026-07-06T03:38:25Z,agent-protocol,after,9716
2026-07-06T03:38:25Z,ts-agent-tooling,before,9716
2026-07-06T03:38:37Z,ts-agent-tooling,after,9663
```

Full logs are saved under `compat-results/ai-ecosystem/20260706T033752Z/logs`.
