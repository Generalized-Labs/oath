# oath

A security-first npm/npx replacement. Faster. Safer. No surprises.

## Install

```sh
curl -fsSL https://oath.sh/install.sh | sh
```

Or via Homebrew:
```sh
brew install generalized-labs/tap/oath
```

## Why oath

- **Script blocking by default** — postinstall scripts only run for packages you trust
- **Behavioral analysis** — detects base64 payloads, dynamic require, env exfiltration at install time
- **Transparency log** — every install appended to `~/.oath/transparency.log`
- **Faster** — 0.9s cold, 0.2s warm (abbreviated packuments, 5-min TTL cache, content-addressable store)
- **Full npm compatibility** — workspaces, git deps, global install, publish, lifecycle scripts

## Commands

```sh
oath install              # install from package.json
oath install express      # add + install
oath install -D typescript # add to devDependencies
oath install -g typescript # global install
oath add lodash            # add dependency
oath remove lodash         # remove dependency
oath run build            # run script with pre/post hooks
oath exec -- prettier .   # run package binary (npx replacement)
oath publish              # publish to npm registry
oath log                  # view transparency log
oath score <pkg>          # security score for a package
```

## Workspaces

oath detects monorepos automatically:
```sh
oath install  # from workspace root — installs all packages, hoists shared deps
```

## Trusted Scripts

Scripts are blocked by default. Allowlist packages:
```json
{
  "trustedDependencies": ["esbuild", "prisma"]
}
```

Or allow all for a project:
```sh
oath install --run-scripts
```

## Requirements

- macOS (arm64, x64) or Linux (x64)
- Node.js (for running installed packages — oath itself needs none)

## License

MIT
