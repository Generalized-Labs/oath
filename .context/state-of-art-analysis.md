# oath: State of the Art Analysis + Gap Assessment

## WHERE OATH STANDS vs THE FIELD

### Detection Capabilities Comparison

| Technique | Socket.dev | Snyk | npm audit | Bun | oath (current) |
|---|---|---|---|---|---|
| Known CVE matching | yes | yes (proprietary DB) | yes (GHSA) | yes | NO |
| Behavioral analysis (static) | yes (70+ checks) | no | no | no | yes (14 detectors) |
| AI/ML malware detection | yes (LLM-based) | no | no | no | NO |
| Install script blocking | warns | no | no | BLOCKS by default | warns |
| Obfuscation detection | yes | no | no | no | yes |
| Typosquatting | yes | no | no | no | yes |
| Manifest confusion | yes | no | no | no | NO |
| Reachability analysis | yes (paid) | yes (paid) | no | no | NO |
| Minimum release age | no | no | no | yes (flag) | NO |
| Safety score | yes (proprietary) | yes (priority) | severity only | no | yes (0-100) |

### What oath MUST add to be world-class:

1. **Install script blocking by default** (Bun proved this works)
2. **Minimum release age** (trivial to implement, blocks most fast-turnaround attacks)
3. **CVE/advisory checking** (hit the npm advisory API -- free, same as npm audit)
4. **Manifest confusion detection** (compare tarball package.json to registry metadata)
5. **Context-aware findings** (dev dep vs prod dep severity adjustment)

### What oath should NOT try to compete on:

1. AI/ML classification (Socket has years of training data, funded team)
2. Reachability analysis (requires call graph construction -- massive effort)
3. Enterprise features (SSO, compliance dashboards -- this is SaaS territory)

---

## CRITICAL COMPATIBILITY GAPS (must fix before real launch)

### P0: Will break immediately on real projects

1. **optionalDependencies + os/cpu/libc filtering**
   - esbuild, swc, lightningcss all use platform-specific optional deps
   - If oath tries to install @esbuild/win32-x64 on macOS, it'll fail
   - MUST skip packages where os/cpu/libc don't match current platform

2. **Package aliases (npm:pkg@version)**
   - `"string-width": "npm:string-width-cjs@4.2.3"` is extremely common
   - Used by every sindresorhus ESM migration
   - Must resolve the REAL package name but install under ALIAS name

3. **Nested node_modules for version conflicts**
   - When two deps need different versions of same package
   - Must nest the less-common version under the requiring package
   - Without this: runtime crashes from wrong version loaded

4. **Hardlink mutation protection**
   - Some packages write to their own directory at runtime
   - With hardlinks, this corrupts the content store
   - Must either: copy (not link) packages with postinstall, or use CoW

5. **.npmrc auth token parsing**
   - `//registry.npmjs.org/:_authToken=${NPM_TOKEN}`
   - Env var substitution, per-scope registries, multi-file merge
   - Without this: can't install private packages

### P1: Will break significant projects

6. **peerDependencies auto-install**
   - React, Vue, Angular ecosystems depend on this
   - npm 7+ auto-installs; must match or fail gracefully

7. **Scoped package registry routing**
   - @company/pkg -> company's private registry
   - Must read .npmrc for per-scope registry config

8. **Lifecycle script env vars**
   - node-gyp needs: npm_config_node_gyp, npm_config_python
   - PATH must include node_modules/.bin
   - npm_lifecycle_event, npm_package_name, npm_package_version

9. **prepare script for git deps**
   - When installing from git, must run `prepare` after clone
   - TypeScript packages compile during prepare

### P2: Needed for adoption but can ship without

10. Workspaces / monorepo support
11. overrides / resolutions
12. bundleDependencies
13. npm link equivalent
14. Reading existing package-lock.json

---

## WHAT MAKES TOOLS GO FROM "PROJECT" TO "STANDARD"

### The Formula (from ripgrep, esbuild, pnpm, bun):

1. **Zero tradeoff for the common case** (ripgrep)
   - oath exec must NEVER be slower than npx
   - oath install can be slower IF the security info is clearly valuable

2. **Become infrastructure, not end-user tool** (esbuild via Vite)
   - Get oath integrated into a popular tool/framework
   - Example: if Turborepo or Nx recommended oath for security...

3. **Escape hatches** (pnpm's shamefully-hoist)
   - `oath install --no-scan` for when you just need speed
   - `oath install --compat` for weird packages
   - NEVER trap users

4. **Crash loudly, never silently corrupt** (bun's rule)
   - If oath doesn't support something, ERROR with a clear message
   - Never silently produce wrong node_modules

5. **Test against real projects** (the adoption gate)
   Must pass (7/10 minimum):
   - [ ] express app (basic server)
   - [ ] Next.js project (complex, many deps)
   - [ ] Vite project (modern tooling)
   - [ ] Create React App (legacy but common)
   - [ ] Prisma project (native binaries, postinstall)
   - [ ] Sharp usage (native module, node-gyp)
   - [ ] Project with TypeScript (tsc in .bin)
   - [ ] Fastify project (moderate)
   - [ ] Project with @scope/packages + private registry
   - [ ] Project with git:// dependencies

### Trust-Breakers (ONE occurrence = devs leave forever):
- Silent node_modules corruption causing runtime errors
- Lockfile that produces different results across runs
- Breaking npm interop (oath install then npm install breaks things)
- Losing/corrupting package.json

### Trust-Builders:
- Obsessively fast GitHub issue responses
- Explicit about what doesn't work yet
- `oath --fallback-to-npm` for unsupported cases
- Blog post with honest benchmarks including where oath loses

---

## THE NPX-FIRST STRATEGY (RECOMMENDED)

Don't try to be a full npm replacement on day one. That's a 6-month war.

Instead:
1. **oath exec** is the hero product (already nearly done)
2. **oath score** is the discovery tool (already done)
3. **oath info** is the transparency tool (already done)
4. **oath install** is the "try it if you want" secondary product

Why npx-first works:
- npx is universally hated (slow, confusing, no info)
- npx has a SIMPLER contract (fetch one package, run binary)
- The security story is strongest for exec (running arbitrary code)
- People who love oath exec will try oath install naturally
- Lower compatibility bar (don't need full node_modules perfection)

---

## WHAT TO BUILD NEXT (priority order)

### Phase 1: Make oath exec world-class (this week)
- [ ] Install script blocking by default (trustedDependencies allowlist)
- [ ] Minimum release age flag (--min-age=7d, configurable)
- [ ] CVE check on exec (hit npm advisory endpoint, show known vulns)
- [ ] Fix: package alias support (npm:pkg@version)
- [ ] Fix: os/cpu/libc filtering for optionalDependencies
- [ ] Context output: show publish date, download count, maintainer count

### Phase 2: Make oath install production-ready (next 2 weeks)
- [ ] Nested node_modules for version conflicts
- [ ] peerDependencies auto-install
- [ ] .npmrc auth token parsing + env var substitution
- [ ] Lifecycle script env vars (full npm_* set)
- [ ] Hardlink mutation protection (copy-on-write for packages with postinstall)
- [ ] Manifest confusion check (tarball vs registry metadata)

### Phase 3: Differentiation (week 3-4)
- [ ] oath policy: declarative security policy file (CI-enforceable)
- [ ] oath diff: show what changed between versions of a package
- [ ] oath watch: monitor your deps for new advisories
- [ ] Private registry support (per-scope routing)

### Phase 4: Distribution + Viral (after Phase 2 passes real-project tests)
- [ ] Record demo video
- [ ] Post thread
- [ ] Submit Show HN
- [ ] Reply to Theo

---

## FALSE POSITIVE REDUCTION STRATEGY

Current oath has HIGH false positive potential because:
- Network access is flagged for EVERY http client library
- Filesystem access is flagged for EVERY file utility
- env access is flagged for EVERY package that reads NODE_ENV

**Fix: Context-aware severity adjustment**

1. **Known-safe patterns list** (curated):
   - axios, node-fetch, undici -> expected to have network access
   - fs-extra, glob, chokidar -> expected to have filesystem access
   - dotenv, cross-env -> expected to have env access
   
2. **Dev dependency downgrade**:
   - If a package is in devDependencies, reduce all findings by 1 level
   - Build tools SHOULD have filesystem access

3. **Popularity-based trust**:
   - >1M weekly downloads AND >2 years old -> reduce severity
   - <100 weekly downloads AND <30 days old -> INCREASE severity

4. **Capability combination scoring**:
   - network alone = low concern
   - env access alone = low concern  
   - network + env access + no readme + <100 downloads = HIGH concern
   - It's the COMBINATION that matters, not individual capabilities

---

## HONEST ASSESSMENT: WHERE WE LOSE TODAY

| Scenario | npm | bun | oath | Winner |
|---|---|---|---|---|
| Cold install speed | 5.4s | 1.1s | 8.6s | bun |
| Warm install speed | 2.0s | 0.2s | 3.6s | bun |
| Ecosystem compat | 100% | 98% | ~70% | npm |
| Security scanning | none | lifecycle blocking | full static analysis | oath |
| exec speed | 2.2s | n/a (no bunx equiv) | 2.2s | tie |
| Enterprise ready | yes | mostly | no | npm |

**oath's honest positioning:**
- We're not the fastest (bun wins on speed)
- We're not the most compatible (npm wins on compat)
- We ARE the only tool that tells you what packages do before running them
- Speed is competitive enough that the security overhead is worth it

---

## KEY INSIGHT FROM RESEARCH

> "Security features that add friction to the happy path get bypassed."
> (Deno lesson)

oath must be:
1. INVISIBLE when things are safe (just installs, no noise)
2. LOUD when things are dangerous (clear, actionable warnings)
3. NEVER blocking legitimate use without an override

The scoring output on every install is too much. Only show findings when score < threshold.
Default: silent install if all packages score B or above. Warn only on C or below. Block on F.
