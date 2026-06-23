# ward

Secure package management for the JavaScript ecosystem.

**ward** is a drop-in replacement for npm/npx that makes security structural, not bolted-on. Written in Rust.

## Why

Every week there's another npm supply chain attack. The current approach (npm + Socket/Snyk bolted on) is failing:
- `npm audit` has a 99% false positive rate. Developers ignore it.
- Install scripts run arbitrary code with full system access.
- Typosquatting is trivially easy.
- No transparency log. You trust the registry blindly.
- npx executes untrusted code with zero sandboxing.

Ward fixes this at the architecture level.

## How it works

### Capability-based permissions
Every package declares what it needs:

```json
{
  "name": "my-package",
  "ward": {
    "permissions": {
      "net": ["api.example.com"],
      "fs_read": ["./config/**"],
      "fs_write": ["./dist/**"],
      "env": ["NODE_ENV", "API_KEY"]
    }
  }
}
```

Packages without a `ward.permissions` declaration are treated as untrusted and sandboxed to pure computation.

### Sandboxed execution (wardx)

```sh
# npx runs arbitrary code with full access. wardx doesn't.
wardx create-react-app my-app

# wardx shows what the package wants:
#   create-react-app requires:
#     network: registry.npmjs.org, github.com
#     write: ./my-app/**
#     run: git
#   [Allow? y/n/always]

# Explicit grants (like Deno):
wardx --allow-net --allow-write=./out some-tool
```

### Transparency log

Every package version is recorded in an append-only Merkle tree (Go's sumdb design). Any mirror is trustworthy because integrity is math, not trust.

```sh
ward verify            # check entire lockfile against transparency log
ward verify express    # check single package
```

### Anti-typosquatting

Publishing `expresss`, `expres`, or `3xpress` is automatically flagged and reviewed. Levenshtein distance + visual similarity + homoglyph detection.

### Built-in behavioral analysis

No $50K/year Socket.dev subscription needed. Ward analyzes packages at publish time:
- Does it access the network? (and where?)
- Does it read environment variables?
- Does it spawn subprocesses?
- Does the declared permissions match actual behavior?

Mismatch = blocked or flagged.

## Architecture

```
crates/
  ward-cli/       # `ward` and `wardx` binaries
  ward-core/      # Shared types, permissions, config
  ward-resolve/   # Dependency resolution
  ward-fetch/     # Registry client + download
  ward-store/     # Content-addressable local store
  ward-sandbox/   # WASM/permission enforcement
  ward-registry/  # Self-hostable registry server
  ward-index/     # Transparency log (Merkle tree)
  ward-analyze/   # Behavioral analysis engine
```

## Compatibility

Ward reads `package.json` and resolves from the npm registry. Your existing projects work without changes. The `ward` section in package.json is optional and additive.

## Status

Early development. Not ready for production use.

## License

MIT - Generalized Labs
