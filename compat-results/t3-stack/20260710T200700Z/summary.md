# T3-Style Stack Compatibility Results

- Date: 2026-07-10
- Oath: `oath 0.1.7`
- Oath SHA-256: `3acfc179d685d06cb60484be73e71b2788053c28d521c9f95a3c876fef4bfe6a`
- Environment: clean temporary project and clean Oath home on macOS arm64
- Overall: pass

## Stack

Next, React, React DOM, tRPC client/server, TanStack Query, SuperJSON, Zod,
AI SDK/OpenAI, Convex, TypeScript, tsx, and Node types.

## Install

- Resolved: 72 packages in 1.3s
- Downloaded: 72 packages / 280.9 MB in 15.4s
- Linked: 72 packages in 5.3s
- Total: 31.7s
- Scanner: Next and `@vercel/oidc` clear; Convex emitted one review warning for
  its explicit credential-and-network login path; no block-tier findings.

## Multiversion Regression

- `esbuild@0.27.0` lock edge: `@esbuild/darwin-arm64@0.27.0`
- `esbuild@0.28.1` lock edge: `@esbuild/darwin-arm64@0.28.1`
- Both installed virtual-store symlinks pointed to the matching platform version.
- No esbuild lifecycle mismatch occurred.

## Runtime

- `oath run smoke`: `{"ready":true,"nextVersion":"16.2.10"}`
- `node node_modules/tsx/dist/cli.mjs --version`: `tsx v4.23.0`, Node `v26.0.0`
- Free disk after the run: 9,080 MiB
