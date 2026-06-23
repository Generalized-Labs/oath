# oath

Secure package management for the JavaScript ecosystem.

**oath** is a drop-in replacement for npm/npx that makes security structural, not bolted-on. Written in Rust.

## Why

Every week there's another npm supply chain attack. The current approach (npm + Socket/Snyk bolted on) is failing:
- `npm audit` has a 99% false positive rate. Developers ignore it.
- Install scripts run arbitrary code with full system access.
- Typosquatting is trivially easy.
- No transparency log. You trust the registry blindly.
- npx executes untrusted code with zero sandboxing.

Oath fixes this at the architecture level.

## How it works

### Capability-based permissions
Every package declares what it needs:

```json
{
  "name": "my-package",
  "oath": {
    "permissions": {
      "net": ["api.example.com"],
      "fs_read": ["./config/**"],
      "fs_write": ["./dist/**"],
      "env": ["NODE_ENV", "API_KEY"]
    }
  }
}
```

Packages without a `oath.permissions` declaration are treated as untrusted and sandboxed to pure computation.

### Sandboxed execution (oathx)

```sh
# npx runs arbitrary code with full access. oathx doesn't.
oathx create-react-app my-app

# oathx shows what the package wants:
#   create-react-app requires:
#     network: registry.npmjs.org, github.com
#     write: ./my-app/**
#     run: git
#   [Allow? y/n/always]

# Explicit grants (like Deno):
oathx --allow-net --allow-write=./out some-tool
```

### Transparency log

Every package version is recorded in an append-only Merkle tree (Go's sumdb design). Any mirror is trustworthy because integrity is math, not trust.

```sh
oath verify            # check entire lockfile against transparency log
oath verify express    # check single package
```

### Anti-typosquatting

Publishing `expresss`, `expres`, or `3xpress` is automatically flagged and reviewed. Levenshtein distance + visual similarity + homoglyph detection.

### Built-in behavioral analysis

No $50K/year Socket.dev subscription needed. Oath analyzes packages at publish time:
- Does it access the network? (and where?)
- Does it read environment variables?
- Does it spawn subprocesses?
- Does the declared permissions match actual behavior?

Mismatch = blocked or flagged.

## Architecture

```
crates/
  oath-cli/       # `oath` and `oathx` binaries
  oath-core/      # Shared types, permissions, config
  oath-resolve/   # Dependency resolution
  oath-fetch/     # Registry client + download
  oath-store/     # Content-addressable local store
  oath-sandbox/   # WASM/permission enforcement
  oath-registry/  # Self-hostable registry server
  oath-index/     # Transparency log (Merkle tree)
  oath-analyze/   # Behavioral analysis engine
```

## Compatibility

Oath reads `package.json` and resolves from the npm registry. Your existing projects work without changes. The `oath` section in package.json is optional and additive.

## Status

Early development. Not ready for production use.

## License

MIT - Generalized Labs
