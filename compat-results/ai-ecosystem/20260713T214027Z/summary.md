# AI Ecosystem Compatibility Results

- Started: 2026-07-13T21:40:27Z
- Finished: 2026-07-13T21:41:32Z
- Oath: oath 0.2.0
- Oath SHA-256: `80ba825559640d3e8725fcefb699dd405d190d5003d50ad820f1889e362e4f8e`
- Overall: pass
- Minimum free-space guard: 650 MiB

## Cases

- `core-ai-sdks`: pass in 18s, packages: `openai ai @ai-sdk/openai @ai-sdk/anthropic zod`
- `convex-cli-sdk`: pass in 17s, packages: `convex`
- `agent-protocol`: pass in 20s, packages: `@modelcontextprotocol/sdk @langchain/core`
- `ts-agent-tooling`: pass in 10s, packages: `typescript tsx @types/node`

## Disk Samples

```csv
timestamp,case,phase,available_mib
2026-07-13T21:40:27Z,core-ai-sdks,before,1251
2026-07-13T21:40:45Z,core-ai-sdks,after,1177
2026-07-13T21:40:45Z,convex-cli-sdk,before,1176
2026-07-13T21:41:02Z,convex-cli-sdk,after,1062
2026-07-13T21:41:02Z,agent-protocol,before,1062
2026-07-13T21:41:22Z,agent-protocol,after,955
2026-07-13T21:41:22Z,ts-agent-tooling,before,955
2026-07-13T21:41:32Z,ts-agent-tooling,after,867
```

Full logs are saved under `compat-results/ai-ecosystem/20260713T214027Z/logs`.
