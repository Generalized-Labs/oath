# oath Viral Marketing Plan

## 1. THE TWEET

```
npx create-whatever runs arbitrary code on your machine with zero warning.

oath exec create-whatever scans it first. Same speed. Shows you what it does before it does it.

Why doesn't npm do this?
```

(274 chars)

### Screenshot description

Split terminal. Left side labeled "npx" shows:
```
$ npx create-sketchy-app
Creating project...
```
No warnings. No info. Just runs.

Right side labeled "oath exec" shows:
```
$ oath exec create-sketchy-app
[SCAN] Analyzing create-sketchy-app@1.2.0...
[WARN] postinstall script detected
[WARN] network access in install phase
[WARN] reads ~/.ssh/id_rsa
[SCORE] 23/100 (F)
[BLOCK] Package failed safety threshold. Run with --force to override.
```

The contrast is immediate. One side is silent. The other side caught something.


## 2. TWITTER THREAD

### Tweet 1 (hook)
```
Every time you run npx, you execute arbitrary code from a stranger on the internet.

No scan. No warning. No permission prompt.

You just trust that "create-next-app" is actually create-next-app and not a typosquat that steals your SSH keys.

This is insane and we all just accept it.
```

### Tweet 2 (demo)
```
Built oath. Drop-in npx replacement written in Rust.

oath exec create-next-app:
- Scans the package for 14 malicious patterns
- Shows you what it accesses before running
- Asks permission if anything looks off
- Then runs it normally

If it finds something bad, it blocks it.
```

### Tweet 3 (speed)
```
"But scanning must be slow"

Benchmarks:
  npx create-next-app: 2.23s
  oath exec create-next-app: 2.24s

10ms difference. oath scans every dependency for data exfiltration, crypto miners, credential harvesting, obfuscated code, and DNS exfil.

npx scans nothing.

Same speed. One protects you.
```

### Tweet 4 (oath score)
```
oath score gives any package a safety rating:

  chalk: A (100/100)
  express: A (96/100)
  lodash: C (73/100)

Checks for typosquatting, slopsquatting, env variable access, postinstall abuse, conditional payloads, and 8 other patterns.

Run it on your dependencies. You might be surprised.
```

### Tweet 5 (agent angle)
```
Here's what keeps me up at night.

AI coding agents run npx. Cursor, Copilot, Devin, every MCP tool. They install packages with zero human review.

An agent can't tell if "lodash" is lodash or "l0dash" stealing your .env. oath can. It blocks it before execution.

This matters more every month.
```

### Tweet 6 (install)
```
oath is open source. MIT licensed. Written in Rust.

cargo install oath-cli

or

curl -fsSL https://oath.dev/install.sh | sh

GitHub: github.com/generalized-labs/oath

Not a company. Not a SaaS. Just a tool that does the obvious thing npm should have done years ago.
```

### Tweet 7 (Theo tag)
```
@t3dotgg you said "better npm is my #1 idea I wish someone would build" and specifically called out npx giving zero info before running packages.

This is that tool. Same speed. Scans first. Blocks bad packages.

Would love your take on the approach.
```


## 3. THEO DM/REPLY STRATEGY

### Reply to his npm video/tweet
```
Built the thing you described. oath is a drop-in npx replacement that scans packages for malicious patterns before executing. Same speed (2.24s vs 2.23s benchmarked). Blocks typosquats, credential harvesters, crypto miners.

Demo: [link to 30s terminal recording]
GitHub: github.com/generalized-labs/oath
```

### Rules
- Reply once. Do not follow up.
- Do not ask him to try it. Just show it exists.
- If he engages, answer questions directly.
- If he doesn't, move on. Other devs will find it.
- Do not DM unless he asks for more info publicly first.
- Best timing: reply within 1 hour of him posting about npm/security/packages.


## 4. HACKER NEWS POST

### Title options (pick one)
1. Show HN: oath -- npx replacement that scans packages before running them
2. Show HN: oath -- security scanner for npm packages, written in Rust
3. Show HN: oath -- what if npx told you what a package does before executing it

### First comment to post

```
Hey HN. I built oath because I got mass-downvoted in a thread last year for pointing out that npx executes arbitrary code with no review step.

oath is a drop-in replacement for npx that scans packages for 14 malicious patterns before executing them. Written in Rust. MIT licensed.

What it checks:
- Data exfiltration (network calls with sensitive data)
- Crypto miners
- Credential harvesting (reads .ssh, .aws, .env)
- Typosquatting (edit distance from popular packages)
- Slopsquatting (AI-hallucinated package names)
- Obfuscated code (entropy analysis)
- Postinstall script abuse
- DNS exfiltration
- Conditional/environment-triggered payloads
- 5 more patterns

Benchmarks (honest):
- oath exec create-next-app: 2.24s
- npx create-next-app: 2.23s
- Overhead: ~10ms for the scan phase

Tradeoffs:
- False positives exist. Some legitimate packages do network calls in postinstall. oath warns but doesn't block unless the score is below threshold.
- The scoring model is heuristic-based, not ML. Simpler to audit, but misses novel attack patterns.
- Currently npm-only. Yarn/pnpm support is planned.
- No Windows support yet. macOS and Linux only.

The "oath score" command gives a 0-100 safety rating for any package. Useful for auditing your lockfile.

Would love technical feedback on the detection heuristics. Source is fully readable.
```


## 5. REDDIT POSTS

### r/node

**Title:** I built an npx replacement that actually tells you what a package does before running it

**Body:**
```
Every npx call executes arbitrary code with no review. We all know this. We all ignore it.

I built oath. Same interface as npx. Same speed (benchmarked within 10ms). But it scans every package for malicious patterns before executing.

What it catches:
- Data exfiltration
- Crypto miners in dependencies
- Credential harvesting
- Typosquats (edit distance detection)
- Obfuscated code
- Postinstall abuse

Example:
  $ oath exec create-next-app
  [SCAN] Analyzing create-next-app@15.3.0
  [OK] Score: 97/100 (A)
  [RUN] Executing...

If it finds something bad, it blocks execution and tells you why.

Written in Rust. MIT licensed. Not a startup, not a SaaS.

GitHub: github.com/generalized-labs/oath

Feedback welcome. Especially interested in false positive reports.
```

### r/javascript

**Title:** oath: security-first npm/npx replacement that scans packages before install/exec

**Body:**
```
Tired of finding out about malicious npm packages after they've already run on thousands of machines.

oath scans for 14 malicious patterns at install/exec time:
- credential harvesting
- crypto miners
- data exfil
- typosquatting
- slopsquatting (AI hallucinated package names that attackers register)
- obfuscated code
- DNS exfiltration
- and more

It assigns a safety score (0-100, letter grade):
  chalk: A (100)
  express: A (96)
  lodash: C (73)

Speed: within 10ms of raw npx on benchmarks.

Rust, MIT, open source: github.com/generalized-labs/oath

The AI agent angle matters here too. Coding assistants run npx commands constantly. They have no way to evaluate whether a package is legitimate. oath gives them (and you) that layer.
```

### r/webdev

**Title:** Why does npx still run arbitrary code with zero warnings in 2026?

**Body:**
```
Genuine question. Every other execution context has sandboxing or at least a permission prompt. Browsers ask before accessing your camera. Mobile apps declare permissions. Docker isolates processes.

npx? Here's some code from a stranger, running with your full user permissions. No scan. No prompt. Hope it's fine.

I built oath to fix this. It's an npx replacement that:
1. Scans the package for malicious patterns (data exfil, crypto miners, credential theft)
2. Shows you a safety score
3. Asks permission if anything looks off
4. Runs it normally if it passes

Same speed as npx. Written in Rust. MIT licensed.

Not trying to sell anything. It's free and open source. Just genuinely confused why the npm ecosystem has accepted this risk for so long.

github.com/generalized-labs/oath
```


## 6. DEMO VIDEO SCRIPT (30 seconds)

### Setup
- Clean terminal, dark theme, large font
- No music. Terminal sounds only.
- Record with asciinema or vhs

### Script

```
[0s] $ npx create-next-app my-app
[2s] (output appears immediately, project starts creating)
[3s] (clear terminal)

[4s] $ # That just ran arbitrary code. No scan. No warning.

[6s] $ oath exec create-next-app my-app
[7s] [SCAN] Analyzing create-next-app@15.3.0...
[7.5s] [CHECK] postinstall scripts... clean
[8s] [CHECK] network access patterns... clean
[8.5s] [CHECK] filesystem access... clean
[9s] [CHECK] obfuscation analysis... clean
[9.5s] [SCORE] 97/100 (A)
[10s] [RUN] Executing create-next-app...
[12s] (normal create-next-app output follows)

[14s] (clear terminal)

[15s] $ # Now let's try something sketchy.

[17s] $ oath exec create-nextt-app
[18s] [SCAN] Analyzing create-nextt-app@0.1.0...
[18.5s] [WARN] Possible typosquat of "create-next-app" (edit distance: 1)
[19s] [WARN] Obfuscated code detected (entropy: 6.8/8.0)
[19.5s] [WARN] Reads process.env and sends to external endpoint
[20s] [WARN] Package published 2 days ago, 3 downloads
[20.5s] [SCORE] 12/100 (F)
[21s] [BLOCK] Package failed safety threshold.
[22s] [BLOCK] This package appears to steal environment variables.
[23s] [BLOCK] Run with --force to override.

[25s] $ # Same speed. One protects you.

[27s] $ oath score lodash
[28s] lodash@4.17.21: 73/100 (C)
[28.5s]   - large dependency surface
[29s]   - no recent security audit
[29.5s]   - broadly trusted by ecosystem

[30s] (cursor blinks)
```

### The "oh shit" moment
Second 18-22. When the typosquat gets caught. The viewer realizes they've run commands like this hundreds of times with npx and never thought twice. That one extra letter in "create-nextt-app" is all it takes. oath caught it. npx would have run it silently.
