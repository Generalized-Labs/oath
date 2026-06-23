//! Pattern definitions for static analysis
//!
//! Encodes knowledge of:
//! - How packages access system resources
//! - Known malicious obfuscation techniques (ua-parser-js, event-stream, node-ipc)
//! - Typosquatting targets

use crate::report::{FindingKind, RiskLevel};

/// A pattern rule: what to detect, what risk it implies
#[derive(Debug, Clone)]
pub struct Pattern {
    pub id: &'static str,
    pub kind: FindingKind,
    pub risk: RiskLevel,
    pub description: &'static str,
    /// String patterns to scan for (fast pre-filter before AST check)
    pub strings: &'static [&'static str],
}

/// All built-in detection patterns
pub static PATTERNS: &[Pattern] = &[
    // ---- NETWORK ----
    Pattern {
        id: "net-fetch",
        kind: FindingKind::Network,
        risk: RiskLevel::Info,
        description: "Uses fetch() API for network requests",
        strings: &["fetch(", "fetch ("],
    },
    Pattern {
        id: "net-http-require",
        kind: FindingKind::Network,
        risk: RiskLevel::Low,
        description: "Requires http/https/net module",
        strings: &[
            "require('http')", "require(\"http\")",
            "require('https')", "require(\"https\")",
            "require('net')", "require(\"net\")",
            "require('tls')", "require(\"tls\")",
            "require('dns')", "require(\"dns\")",
        ],
    },
    Pattern {
        id: "net-axios",
        kind: FindingKind::Network,
        risk: RiskLevel::Info,
        description: "Uses axios for HTTP requests",
        strings: &["require('axios')", "require(\"axios\")", "from 'axios'", "from \"axios\""],
    },
    Pattern {
        id: "net-got",
        kind: FindingKind::Network,
        risk: RiskLevel::Info,
        description: "Uses got/node-fetch for HTTP requests",
        strings: &["require('got')", "require('node-fetch')", "require(\"got\")", "require(\"node-fetch\")"],
    },
    Pattern {
        id: "net-socket-connect",
        kind: FindingKind::Network,
        risk: RiskLevel::Medium,
        description: "Creates raw TCP/socket connection",
        strings: &[".connect(", "net.createConnection", "new net.Socket"],
    },

    // ---- FILESYSTEM ----
    Pattern {
        id: "fs-require",
        kind: FindingKind::Filesystem,
        risk: RiskLevel::Low,
        description: "Requires fs module",
        strings: &[
            "require('fs')", "require(\"fs\")",
            "require('fs/promises')", "require(\"fs/promises\")",
            "require('node:fs')", "require(\"node:fs\")",
        ],
    },
    Pattern {
        id: "fs-write-home",
        kind: FindingKind::Filesystem,
        risk: RiskLevel::High,
        description: "Writes to home directory or system paths",
        strings: &[
            "process.env.HOME", "os.homedir()",
            "~/.ssh", "~/.aws", "~/.npmrc",
            "/.ssh/", "/.aws/credentials",
        ],
    },
    Pattern {
        id: "fs-read-sensitive",
        kind: FindingKind::Filesystem,
        risk: RiskLevel::High,
        description: "Reads SSH keys, credential paths, or /etc/passwd",
        strings: &[
            "id_rsa", "id_ed25519",
            "/.ssh/", "/.aws/credentials",
            "/etc/passwd", "/etc/shadow",
        ],
    },

    // ---- ENV ACCESS ----
    Pattern {
        id: "env-sensitive",
        kind: FindingKind::EnvAccess,
        risk: RiskLevel::High,
        description: "Accesses sensitive environment variables (tokens/keys/secrets)",
        strings: &[
            "NPM_TOKEN",
            "AWS_SECRET",
            "AWS_ACCESS_KEY",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "API_KEY",
            "SECRET_KEY",
            "PRIVATE_KEY",
            "DATABASE_URL",
            "CI_TOKEN",
            "SLACK_TOKEN",
            "DISCORD_TOKEN",
        ],
    },
    Pattern {
        id: "env-access",
        kind: FindingKind::EnvAccess,
        risk: RiskLevel::Info,
        description: "Reads environment variables",
        strings: &["process.env"],
    },

    // ---- SUBPROCESS ----
    Pattern {
        id: "subprocess-require",
        kind: FindingKind::Subprocess,
        risk: RiskLevel::Medium,
        description: "Requires child_process module",
        strings: &[
            "require('child_process')", "require(\"child_process\")",
            "require('node:child_process')", "require(\"node:child_process\")",
        ],
    },
    Pattern {
        id: "subprocess-exec",
        kind: FindingKind::Subprocess,
        risk: RiskLevel::High,
        description: "Executes shell commands",
        strings: &[
            ".execSync(", ".spawnSync(", ".execFileSync(",
            "child_process.exec(", "shelljs", "shell.exec(",
            "require('shelljs')", "require(\"shelljs\")",
        ],
    },

    // ---- DYNAMIC EXEC ----
    Pattern {
        id: "eval-direct",
        kind: FindingKind::DynamicExec,
        risk: RiskLevel::High,
        description: "Uses eval() for dynamic code execution",
        strings: &["eval(", " eval "],
    },
    Pattern {
        id: "eval-function",
        kind: FindingKind::DynamicExec,
        risk: RiskLevel::High,
        description: "Uses new Function() for dynamic code execution",
        strings: &["new Function(", "new Function ("],
    },
    Pattern {
        id: "eval-vm",
        kind: FindingKind::DynamicExec,
        risk: RiskLevel::High,
        description: "Uses Node.js vm module for dynamic execution",
        strings: &[
            "require('vm')", "require(\"vm\")",
            "vm.runInNewContext", "vm.runInThisContext",
            "vm.Script",
        ],
    },
    Pattern {
        id: "eval-settimeout-string",
        kind: FindingKind::DynamicExec,
        risk: RiskLevel::High,
        description: "Passes string to setTimeout/setInterval (dynamic exec)",
        strings: &["setTimeout(\"", "setInterval(\"", "setTimeout('", "setInterval('"],
    },

    // ---- OBFUSCATION ----
    Pattern {
        id: "obfus-buffer-from",
        kind: FindingKind::Obfuscation,
        risk: RiskLevel::Medium,
        description: "Uses Buffer.from() to decode hidden strings (common obfuscation)",
        strings: &["Buffer.from(", "Buffer.from ("],
    },
    Pattern {
        id: "obfus-atob",
        kind: FindingKind::Obfuscation,
        risk: RiskLevel::Medium,
        description: "Uses atob/btoa for base64 encoding (potential obfuscation)",
        strings: &["atob(", "btoa("],
    },
    Pattern {
        id: "obfus-charcode",
        kind: FindingKind::Obfuscation,
        risk: RiskLevel::Medium,
        description: "Builds strings from char codes (obfuscation technique)",
        strings: &["fromCharCode(", "String.fromCharCode"],
    },
    Pattern {
        id: "obfus-hex-string",
        kind: FindingKind::Obfuscation,
        risk: RiskLevel::Low,
        description: "Contains long hex-encoded strings",
        strings: &["\\x", "0x", "\\u00"],
    },

    // ---- DATA EXFILTRATION ----
    Pattern {
        id: "exfil-dns",
        kind: FindingKind::DataExfiltration,
        risk: RiskLevel::Critical,
        description: "DNS exfiltration pattern detected",
        strings: &[
            "dns.lookup(", "dns.resolve(",
            ".nip.io", ".burpcollaborator", ".ngrok.io",
        ],
    },
    // ---- CRYPTO MINING ----
    Pattern {
        id: "crypto-miner",
        kind: FindingKind::CryptoMiner,
        risk: RiskLevel::Critical,
        description: "Possible cryptocurrency mining code",
        strings: &[
            "coinhive", "cryptonight", "stratum+tcp://",
            "monero", "xmrig", "CoinHive",
            "mining", "hashrate",
        ],
    },
];

/// Popular package names that are typosquatting targets
/// If a package name is similar to these but NOT these, flag it
pub static POPULAR_PACKAGES: &[&str] = &[
    "react", "vue", "angular", "svelte",
    "express", "fastify", "koa", "hapi",
    "lodash", "underscore", "ramda",
    "axios", "got", "node-fetch", "superagent",
    "webpack", "vite", "rollup", "esbuild", "parcel",
    "typescript", "babel", "eslint", "prettier",
    "jest", "mocha", "vitest", "ava",
    "mongoose", "sequelize", "prisma", "typeorm",
    "socket.io", "ws", "socket",
    "moment", "dayjs", "date-fns",
    "dotenv", "config", "convict",
    "colors", "chalk", "kleur", "picocolors",
    "commander", "yargs", "minimist", "meow",
    "uuid", "nanoid", "shortid",
    "bcrypt", "bcryptjs", "jsonwebtoken", "passport",
    "multer", "busboy", "formidable",
    "nodemailer", "sendgrid",
    "redis", "ioredis", "memcached",
    "aws-sdk", "@aws-sdk/client-s3",
    "stripe", "paypal",
    "sharp", "jimp", "canvas",
    "cheerio", "puppeteer", "playwright",
    "cross-env", "dotenv-cli",
    "rimraf", "mkdirp", "glob", "minimatch",
    "semver", "nvm", "node-gyp",
];
