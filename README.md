# oath

**npm runs code. oath asks permission first.**

---

- Scans every package for malware before it touches your machine. 14 pattern detectors. Zero trust.
- Drop-in replacement for npm/npx. Same commands, same registry, full security analysis on every install and exec.
- Safety scores (0-100) for any package. Know what you're importing before you import it.

## Install

```sh
curl -fsSL https://oath.dev/install.sh | sh
```

Or via Homebrew:

```sh
brew install generalized-labs/tap/oath
```

## Usage

```sh
# Install dependencies (scans everything, blocks threats)
oath install

# Execute a package (prompts for permissions first)
oath exec cowsay "hello world"

# Check a package safety score before you commit to it
oath score express
#  express@5.2.1 -- 96/100 (A)

# Deep package intel
oath info lodash

# Full audit of your dependency tree
oath audit
```

## npx vs oath exec

```
┌─────────────────────────────────┬──────────────────────────────────────────────┐
│  $ npx cowsay "hi"              │  $ oath exec cowsay "hi"                     │
│                                 │                                              │
│  Need to install the following  │  oath | fetching cowsay@1.6.0                │
│  packages: cowsay@1.6.0        │  oath | scanning 1 package (14 detectors)    │
│  Ok to proceed? (y)            │  oath | score: 88/100 (B+)                   │
│                                 │  oath | capabilities: [fs:read, env:read]    │
│                                 │  oath | no malicious patterns detected       │
│  (runs immediately)             │                                              │
│                                 │  Allow cowsay to run? [y/n/always]           │
│                                 │                                              │
│                                 │  (runs after informed consent)               │
└─────────────────────────────────┴──────────────────────────────────────────────┘
```

npx tells you a name. oath tells you what it does.

## Benchmarks

Machine: Apple M1, macOS 15.6.1, Node v22.12.0

### Cold install (empty cache, no lockfile)

| Project | npm | bun | oath | Security overhead |
|---------|-----|-----|------|-------------------|
| 3 deps | 1.78s | 0.23s | 0.22s | scans 3 packages |
| 93 deps | 3.12s | 0.72s | 2.35s | scans 7 new packages |
| 163 deps | 5.43s | 1.08s | 8.60s | scans 69 new packages |

### Package execution (npx vs oath exec)

| Scenario | npx | oath exec | Notes |
|----------|-----|-----------|-------|
| Cold (cowsay) | 2.67s | 2.44s | oath fetches, resolves, scans, runs |
| Warm (cached) | 2.23s | 2.24s | oath still scans before running |

oath exec matches npx speed while running full security analysis on every invocation.

## How it works

**Parser.** OXC-based JavaScript/TypeScript parser. Fast enough to scan hundreds of files during install without you noticing.

**Detectors.** 14 pattern detectors run in parallel: data exfiltration, credential harvesting, crypto mining, install script abuse, dynamic code execution, typosquatting signals, obfuscated payloads, and more.

**Store.** BLAKE3 content-addressable package store. Deduplicated. Integrity-verified. Every artifact is hashed before it enters the cache.

**Resolver.** Level-parallel dependency resolver. Resolves entire dependency levels concurrently instead of walking the tree node-by-node.

## All commands

```
oath install      Install dependencies from package.json
oath add          Add a package
oath remove       Remove a package
oath run          Run a script from package.json
oath exec         Execute a package binary (npx replacement)
oath audit        Audit installed dependencies
oath score        Get safety score for any package
oath info         Package metadata and capability report
oath perms        View/manage permission grants
oath init         Initialize a new project
oath why          Explain why a package is in your tree
oath licenses     List all licenses in your dependency tree
oath verify       Verify integrity of installed packages
oath graph        Visualize your dependency graph
```

## Roadmap

- [ ] ML-based malware classifier trained on known supply chain attacks
- [ ] Private registry support (Artifactory, Verdaccio, GitHub Packages)
- [ ] CI integration (GitHub Actions, GitLab CI) with policy-as-code
- [ ] VS Code extension with inline safety scores

## The name

Packages swear an oath. Break it, get blocked.

## License

MIT
