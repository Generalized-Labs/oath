# oath Deep Research — June 2025

## THE CORE THESIS (what research confirms)

npm is not a package manager with security bolted on.
It is a code execution platform disguised as a package manager.
Every `npm install` runs arbitrary code on your machine.
Every `npx anything` downloads and executes unknown code with full OS permissions.
Nobody is fixing this. oath will.

---

## DEV COMMUNITY PAIN POINTS

### npm specific
- **postinstall scripts run silently** — no prompt, no summary, full OS access. This is the #1 attack vector.
- **npx is drive-by execution** — `npx create-some-app` downloads and runs arbitrary code with zero sandboxing. No prompt. No audit. Just exec.
- **lockfile poisoning** — attackers can manipulate package-lock.json to swap in malicious versions without changing package.json. npm audit doesn't catch this.
- **hoisting creates phantom deps** — can `require()` packages you didn't declare, breaks reproducibility, causes "works on my machine" bugs constantly.
- **npm audit is noise** — flags hundreds of low-severity CVEs with no actionable guidance. Developers learn to ignore it. It cries wolf so loudly the real threats get missed.
- **publish 2FA bypass** — multiple incidents where attackers bypassed npm 2FA via automation tokens.
- **`files` field ignored** — packages routinely publish .env, credentials, internal configs accidentally.
- **bin entry hijacking** — malicious packages can shadow system binaries via bin entries in node_modules/.bin/

### npx specific
- **zero security model** — `npx <anything>` fetches and executes latest version with no integrity check beyond the moment of fetch.
- **name squatting** — `npx create-react-aap` (typo) = own the machine.
- **no version pinning by default** — every run can pull a different version.
- **caching is a lie** — cached version can be a different version than what's in your lockfile.
- **Theo has explicitly said "never run npx"** on stream multiple times — his audience (TypeScript devs, T3 stack users) are already primed for an alternative.

### bun specific
- **runs postinstall scripts with full permissions** — same as npm, no sandbox.
- **lockfile format is binary/opaque** — `bun.lockb` is not human-readable, can't diff it in PRs, security teams hate it. bun v1.1+ added `bun.lock` (text) but adoption is uneven.
- **compatibility gaps** — lifecycle scripts, workspace edge cases, some native modules fail.
- **`bunx` is just npx with a speed coat** — same security model: zero.
- **speed without safety** — bun's entire identity is speed. Security is an afterthought.
- **no permission model** — bun doesn't even attempt to sandbox package scripts.
- **GitHub issues**: hundreds of reports of install producing different results than npm for complex workspaces.

### pnpm specific
- **still runs postinstall** — pnpm's strict symlinks don't stop postinstall scripts.
- **complex to configure** — `.npmrc`, `pnpm-workspace.yaml`, `shamefully-hoist` flags confuse people.
- **no integrated security** — pnpm's killer feature is disk efficiency, not security.
- **`pnpm dlx`** = same drive-by problem as npx.

---

## SUPPLY CHAIN ATTACKS (the real ammo)

### Confirmed major incidents

**event-stream (2018)** — 2M weekly downloads. Attacker gained maintainer access, added flatmap-stream dep that targeted bitcoin wallets. First major wake-up call. npm did nothing proactive.

**ua-parser-js (2021)** — 8M weekly downloads. Account compromised, malicious versions published, ran cryptominer + credential stealer via postinstall script. 3 versions live for hours.

**colors.js + faker.js (2022)** — Marak Squibb (maintainer) intentionally sabotaged his own packages used by 22,000+ projects. Exposed total dependency on maintainer goodwill.

**node-ipc (2022)** — "protestware" — maintainer added code that wiped files if IP was Russian/Belarusian. ran via postinstall. nobody stopped it.

**polyfill.io (June 2024)** — CDN bought by Chinese company, 100,000+ websites injected with malware via script tag. Not npm, but same trust model. Huge developer wake-up moment.

**npm malware surge 2024** — Checkmarx, Socket.dev, and Phylum reported 700%+ increase in malicious npm packages in 2024. Most delivered via postinstall scripts.

**PyPI/npm crossover typosquatting (2024)** — "requests" (Python) typosquatted on npm as "request" (legitimate package), people installing wrong thing and getting malware.

**LLM-hallucinated packages (2024-2025)** — ChatGPT/Copilot suggests non-existent package names. Attackers register those names with malware. "slopsquatting."

### The attack anatomy (always the same)
1. Publish package with legitimate-sounding name
2. Add postinstall script that runs on install
3. Script exfiltrates env vars (AWS keys, tokens, secrets)
4. OR downloads second-stage payload (evades static analysis)
5. OR waits for specific conditions (version, OS, env vars) before activating

### What oath can stop that nothing else does
- **Permission prompt before any postinstall runs** — user sees exactly what it wants to do
- **Env variable stripping** — AWS_SECRET_KEY etc. not visible to install scripts
- **Static analysis before install** — flag high-risk patterns before download completes
- **Transparency log** — every install recorded with hashes, what scripts ran, what they accessed
- **Lockfile integrity** — lock to exact SRI hashes, detect if lockfile was tampered

---

## COMPETITOR GAP ANALYSIS

### Socket.dev
- **What it does**: 70+ risk signals, AST-based static analysis, GitHub PR integration
- **What it misses**: runtime behavior, env exfiltration at install time, no execution sandbox
- **Price**: $19-$99/mo per user. Expensive for indie devs.
- **Gap**: No CLI-native workflow. It's a service, not a tool you own.

### Snyk
- **CVE-only** — doesn't detect new/zero-day supply chain attacks
- **Noise machine** — thousands of alerts, developers learn to ignore
- **No runtime protection**

### npm audit
- **Advisory database only** — only catches known CVEs, nothing novel
- **No behavioral analysis**
- **False positive rate** destroys trust

### Deno
- **Permission model is real** — `--allow-net`, `--allow-read`, `--allow-env` per process
- **But**: breaks npm ecosystem entirely. Can't just drop it in.
- **Lesson**: granular permissions work; oath should apply same model to install scripts

### cargo-deny (Rust ecosystem — learn from this)
- License checks on all deps
- Advisory database integration (RustSec)
- Duplicate dep detection (why do you have 3 versions of the same crate?)
- Ban specific packages org-wide
- **This is what oath-policy.toml should look like**

---

## WHAT THEO + HIS AUDIENCE CARE ABOUT

### Theo's stack and audience
- T3 stack (Next.js, TypeScript, Tailwind, tRPC, Prisma)
- Billions of npm installs across his tutorials
- Has said "just use bun" many times — but bun has let him down on compatibility
- Strong opinions on DX: if it's not fast and obvious, it's wrong
- Will roast tools publicly if they fail him

### What would make Theo switch and evangelize oath
1. **`oath install` is faster than bun** (even if marginally — he will notice and tweet)
2. **The security prompt UX is a moment** — when it blocks something real, he screenshots it
3. **It works with his entire stack** — Next.js, Turborepo, pnpm workspaces compat
4. **`oath why <package>`** — explains exactly why a package was flagged. Devs love this.
5. **No breaking changes** — drops in as `npm install` replacement, package.json unchanged
6. **The name and copy is provocative** — "npm trusts everyone. You shouldn't." = tweet bait

### What ThePrimeagen cares about
- Rust (oath IS Rust — instant credibility)
- Performance numbers (we need benchmarks)
- Security that doesn't get in the way
- OSS, not a SaaS gate

### What the broader TypeScript dev community wants
- **Workspaces that work** — monorepo first-class support
- **Type-check before install?** (novel — nobody does this)
- **Package.json validation** — catch bad configs before they break CI
- **Offline mode** — lock + cache = fully reproducible builds with no network
- **Diff-friendly lockfiles** — text-based, human-readable, shows what changed

---

## FEATURES OATH NEEDS (priority ranked)

### P0 — Blockers to adoption (ship these or nobody switches)

1. **Workspace/monorepo support** — workspaces: [] in package.json, link local packages
2. **Scripts runner** — `oath run build` etc. (currently missing from CLI review)
3. **Human-readable lockfile** — `oath.lock` in TOML or pretty JSON, diffable in PRs
4. **`oath why <package>`** — explains why a dep is in your tree + risk assessment
5. **Drop-in compatibility** — reads package.json, reads package-lock.json and pnpm-lock.yaml
6. **Progress output** — real-time install progress (fetching X of Y, linking...)

### P1 — Core differentiators (what makes oath OATH)

7. **Pre-install static analysis** — scan before executing, show risk report
8. **Permission prompt for postinstall** — "this package wants to run: [script]. Allow? [y/N/sandbox]"
9. **oath-policy.toml** — org-wide rules: ban licenses, ban packages, require approval
10. **Transparency log** — `~/.oath/audit.log` with every install, what scripts ran, SRI hashes
11. **Env stripping** — configurable allowlist, strip secrets before any script runs
12. **`oath exec` / `oathx` with permission prompts** — npx replacement with "this package wants net access, allow?"
13. **Lockfile integrity check** — `oath verify` — detect tampered lockfiles

### P2 — Makes devs love it

14. **`oath outdated`** — show outdated packages with security changelog
15. **`oath licenses`** — report all licenses in your dep tree (cargo-deny style)
16. **`oath why-not <package>`** — explain why something was blocked by policy
17. **`oath graph`** — visual dep tree in terminal (ASCII of course)
18. **Offline mode** — `--offline` uses only cache, reproducible builds
19. **Install benchmarks** — `oath install --bench` shows timing breakdown
20. **`oath doctor`** — diagnose broken node_modules, phantom deps, version mismatches

### P3 — Enterprise and CI

21. **oath-server** — private registry proxy with policy enforcement
22. **SBOM export** — CycloneDX/SPDX format for compliance
23. **GitHub Actions integration** — `oath ci` mode for reproducible CI installs
24. **`oath diff`** — show what changed between two lockfiles

---

## POSITIONING INSIGHT

The real gap: **nobody makes security feel like power**.

npm audit feels like homework.
Socket.dev feels like surveillance.
oath should feel like a weapon.

The developer who uses oath is the developer who doesn't get pwned.
That's the identity hook. Not "we protect you" — "you protect yourself."

Target copy: second person, threat-forward, never passive voice.
"Your postinstall script just tried to read AWS_SECRET_ACCESS_KEY. oath stopped it."
THAT is the screenshot that goes viral on Twitter.

---

## BENCHMARK TARGETS

We need to beat bun on express install (71 packages):
- bun install: ~0.6s (warm cache)
- pnpm install: ~2s (warm)  
- npm install: ~8s (warm)
- oath target: <0.5s warm, <3s cold

Key insight: with BLAKE3 + hardlinks + parallel fetch we can beat bun on cache hits.
Cold install we won't beat bun's C++ but we can beat npm/pnpm.

---

## SLOPSQUATTING (2025 threat, nobody is talking about it)

LLMs hallucinate package names. Attackers register those names.
oath can integrate with a "known hallucination" database.
Flag packages that look like common LLM hallucinations.
This is a 2025-specific differentiator nobody else has.

oath can add: "This package name matches known LLM-hallucinated names. Verify this is what you intended."
