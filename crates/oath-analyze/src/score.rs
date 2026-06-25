//! Safety score computation for packages

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::report::{AnalysisReport, FindingKind, RiskLevel};

/// A factor that contributed to the safety score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreFactor {
    pub name: String,
    pub weight: i16,
    pub description: String,
}

/// Computed safety score for a package (0-100, higher = safer)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyScore {
    pub score: u8,
    pub grade: char,
    pub factors: Vec<ScoreFactor>,
}

fn score_to_grade(score: u8) -> char {
    match score {
        90..=100 => 'A',
        75..=89 => 'B',
        60..=74 => 'C',
        40..=59 => 'D',
        _ => 'F',
    }
}

/// Context for scoring -- reduces false positives by understanding what the package IS
#[derive(Debug, Clone, Default)]
pub struct ScoreContext {
    /// Whether this is a devDependency (build tool, test framework, etc.)
    pub is_dev: bool,
    /// Weekly download count from registry (0 = unknown)
    pub weekly_downloads: u64,
    /// Package age in days (0 = unknown)
    pub age_days: u32,
}

/// Known-safe package patterns: packages whose ENTIRE PURPOSE is the flagged capability.
/// We suppress capability penalties for these.
const KNOWN_NETWORK_PACKAGES: &[&str] = &[
    "axios",
    "node-fetch",
    "undici",
    "got",
    "request",
    "superagent",
    "ky",
    "cross-fetch",
    "isomorphic-fetch",
    "whatwg-fetch",
    "needle",
    "phin",
];
const KNOWN_FS_PACKAGES: &[&str] = &[
    "fs-extra",
    "graceful-fs",
    "glob",
    "globby",
    "chokidar",
    "rimraf",
    "del",
    "mkdirp",
    "make-dir",
    "find-up",
    "locate-path",
    "fast-glob",
];
const KNOWN_ENV_PACKAGES: &[&str] = &["dotenv", "cross-env", "env-ci", "envinfo"];
const KNOWN_EXEC_PACKAGES: &[&str] = &["execa", "cross-spawn", "shelljs", "npm-run-all"];

fn is_known_safe_for_capability(name: &str, capability: &str) -> bool {
    match capability {
        "network" => KNOWN_NETWORK_PACKAGES.contains(&name),
        "filesystem" => KNOWN_FS_PACKAGES.contains(&name),
        "env_access" => KNOWN_ENV_PACKAGES.contains(&name),
        "subprocess" | "dynamic_exec" => KNOWN_EXEC_PACKAGES.contains(&name),
        _ => false,
    }
}

/// Compute a safety score with context awareness (preferred)
pub fn compute_safety_score_contextual(
    report: &AnalysisReport,
    package_dir: &Path,
    ctx: &ScoreContext,
) -> SafetyScore {
    let mut score = compute_safety_score_inner(report, package_dir, Some(ctx));

    // Dev dependency discount: reduce penalties by 40% (build tools SHOULD have capabilities)
    if ctx.is_dev && score.score < 100 {
        let lost = 100i32 - score.score as i32;
        let recovered = (lost * 40) / 100;
        score.score = (score.score as i32 + recovered).clamp(0, 100) as u8;
        score.grade = score_to_grade(score.score);
        if recovered > 0 {
            score.factors.push(ScoreFactor {
                name: "dev_dependency".into(),
                weight: recovered as i16,
                description: "Dev dependency (reduced severity)".into(),
            });
        }
    }

    // Popularity trust: a very widely-used package (>=1M weekly downloads) whose
    // only flags are heuristic -- i.e. NO critical real-malware finding -- is almost
    // certainly a false positive (a code formatter using fromCharCode, a DB driver
    // with a prepare script). Supply-chain compromises of popular packages surface
    // as CRITICAL decode->exec / exfiltration findings, which we deliberately never
    // rescue, so recall on real attacks is preserved.
    let has_critical = report
        .findings
        .iter()
        .any(|f| matches!(f.risk, RiskLevel::Critical));
    if ctx.weekly_downloads >= 1_000_000 && !has_critical {
        let floor = 90u8; // grade A
        if score.score < floor {
            let recovered = floor as i16 - score.score as i16;
            score.score = floor;
            score.grade = score_to_grade(score.score);
            score.factors.push(ScoreFactor {
                name: "trusted_popular".into(),
                weight: recovered,
                description: format!(
                    "{}M+ weekly downloads, no critical findings (heuristic flags treated as false positives)",
                    ctx.weekly_downloads / 1_000_000
                ),
            });
        }
    }

    // Suspicion boost: <100 weekly downloads + <30 days old = extra penalty
    if ctx.weekly_downloads > 0 && ctx.weekly_downloads < 100 && ctx.age_days < 30 {
        let penalty = -15i16;
        score.score = (score.score as i32 + penalty as i32).max(0) as u8;
        score.grade = score_to_grade(score.score);
        score.factors.push(ScoreFactor {
            name: "new_unpopular".into(),
            weight: penalty,
            description: "New package with very few downloads".into(),
        });
    }

    score
}

/// Compute a safety score for a package based on analysis results and package directory contents.
pub fn compute_safety_score(report: &AnalysisReport, package_dir: &Path) -> SafetyScore {
    compute_safety_score_inner(report, package_dir, None)
}

fn compute_safety_score_inner(
    report: &AnalysisReport,
    package_dir: &Path,
    _ctx: Option<&ScoreContext>,
) -> SafetyScore {
    let mut factors: Vec<ScoreFactor> = Vec::new();
    let mut raw_score: i32 = 100;

    // Count findings by risk level
    let mut critical_count = 0u32;
    let mut high_count = 0u32;
    let mut medium_count = 0u32;
    let mut low_count = 0u32;

    for finding in &report.findings {
        match finding.risk {
            RiskLevel::Critical => critical_count += 1,
            RiskLevel::High => high_count += 1,
            RiskLevel::Medium => medium_count += 1,
            RiskLevel::Low => low_count += 1,
            _ => {}
        }
    }

    if critical_count > 0 {
        let penalty = -(critical_count as i16 * 30);
        factors.push(ScoreFactor {
            name: "critical_findings".into(),
            weight: penalty,
            description: format!("{} critical finding(s)", critical_count),
        });
        raw_score += penalty as i32;
    }

    if high_count > 0 {
        let penalty = -(high_count as i16 * 15);
        factors.push(ScoreFactor {
            name: "high_findings".into(),
            weight: penalty,
            description: format!("{} high finding(s)", high_count),
        });
        raw_score += penalty as i32;
    }

    if medium_count > 0 {
        let penalty = -(medium_count as i16 * 5);
        factors.push(ScoreFactor {
            name: "medium_findings".into(),
            weight: penalty,
            description: format!("{} medium finding(s)", medium_count),
        });
        raw_score += penalty as i32;
    }

    if low_count > 0 {
        let penalty = -(low_count as i16 * 2);
        factors.push(ScoreFactor {
            name: "low_findings".into(),
            weight: penalty,
            description: format!("{} low finding(s)", low_count),
        });
        raw_score += penalty as i32;
    }

    // Capability-based penalties (suppress for known-safe packages)
    let pkg_name = &report.package_name;

    if report.capabilities.has_install_scripts {
        factors.push(ScoreFactor {
            name: "install_scripts".into(),
            weight: -10,
            description: "Package has install scripts".into(),
        });
        raw_score -= 10;
    }

    if report.capabilities.network
        && report.capabilities.env_access
        && !is_known_safe_for_capability(pkg_name, "network")
        && !is_known_safe_for_capability(pkg_name, "env_access")
    {
        factors.push(ScoreFactor {
            name: "network_env_combo".into(),
            weight: -20,
            description: "Network access combined with environment variable access".into(),
        });
        raw_score -= 20;
    }

    if report.capabilities.dynamic_exec && !is_known_safe_for_capability(pkg_name, "dynamic_exec") {
        factors.push(ScoreFactor {
            name: "dynamic_exec".into(),
            weight: -10,
            description: "Uses dynamic code execution (eval/Function)".into(),
        });
        raw_score -= 10;
    }

    // Check for HIGH/CRITICAL obfuscation findings only (Medium ones are often false positives)
    let high_obfuscation = report.findings.iter().any(|f| {
        f.kind == FindingKind::Obfuscation
            && matches!(f.risk, RiskLevel::High | RiskLevel::Critical)
    });
    if high_obfuscation {
        factors.push(ScoreFactor {
            name: "obfuscated_code".into(),
            weight: -25,
            description: "Obfuscated code detected".into(),
        });
        raw_score -= 25;
    }

    // ---- Advanced obfuscation scoring (Feature 2) ----
    // Base64 payload: High obfuscation findings containing "Base64 payload"
    let base64_payload_count = report
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::Obfuscation && f.message.contains("Base64 payload"))
        .count() as i32;
    if base64_payload_count > 0 {
        let penalty = -(base64_payload_count * 30).min(60) as i16;
        factors.push(ScoreFactor {
            name: "base64_payload".into(),
            weight: penalty,
            description: format!(
                "{} base64 payload detection(s) (Buffer.from/atob with encoded data)",
                base64_payload_count
            ),
        });
        raw_score += penalty as i32;
    }

    // Dynamic require obfuscation
    let dyn_req_count = report
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::Obfuscation && f.message.contains("Dynamic require"))
        .count() as i32;
    if dyn_req_count > 0 {
        let penalty = -(dyn_req_count * 25).min(50) as i16;
        factors.push(ScoreFactor {
            name: "dynamic_require_obfuscation".into(),
            weight: penalty,
            description: format!(
                "{} dynamic require obfuscation(s) (concatenated module names)",
                dyn_req_count
            ),
        });
        raw_score += penalty as i32;
    }

    // Hex string execution
    let hex_exec_count = report
        .findings
        .iter()
        .filter(|f| {
            f.kind == FindingKind::Obfuscation && f.message.contains("Hex string execution")
        })
        .count() as i32;
    if hex_exec_count > 0 {
        let penalty = -(hex_exec_count * 40).min(80) as i16;
        factors.push(ScoreFactor {
            name: "hex_string_execution".into(),
            weight: penalty,
            description: format!(
                "{} hex string execution(s) (eval+fromCharCode or hex eval)",
                hex_exec_count
            ),
        });
        raw_score += penalty as i32;
    }

    // Env exfiltration combo
    let env_exfil_count = report
        .findings
        .iter()
        .filter(|f| {
            f.kind == FindingKind::DataExfiltration
                && f.message.contains("Environment variable exfiltration")
        })
        .count() as i32;
    if env_exfil_count > 0 {
        let penalty = -(env_exfil_count * 35).min(70) as i16;
        factors.push(ScoreFactor {
            name: "env_exfiltration_combo".into(),
            weight: penalty,
            description: format!(
                "{} file(s) with process.env read + HTTP request (possible exfiltration)",
                env_exfil_count
            ),
        });
        raw_score += penalty as i32;
    }

    // Cryptocurrency wallet patterns
    let crypto_wallet_count = report
        .findings
        .iter()
        .filter(|f| f.kind == FindingKind::CryptoMiner && f.message.contains("wallet address"))
        .count() as i32;
    if crypto_wallet_count > 0 {
        let penalty = -(crypto_wallet_count * 20).min(60) as i16;
        factors.push(ScoreFactor {
            name: "crypto_wallet_patterns".into(),
            weight: penalty,
            description: format!(
                "{} cryptocurrency wallet address(es) detected",
                crypto_wallet_count
            ),
        });
        raw_score += penalty as i32;
    }

    // Directory-based checks
    let has_readme = package_dir.join("README.md").exists()
        || package_dir.join("readme.md").exists()
        || package_dir.join("README").exists()
        || package_dir.join("README.txt").exists()
        || package_dir.join("README.rst").exists();

    if !has_readme {
        factors.push(ScoreFactor {
            name: "no_readme".into(),
            weight: -5,
            description: "Package has no README".into(),
        });
        raw_score -= 5;
    }

    // Count files
    let file_count = walkdir::WalkDir::new(package_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count();

    if file_count > 200 {
        factors.push(ScoreFactor {
            name: "large_surface_area".into(),
            weight: -5,
            description: format!("Package has {} files (large surface area)", file_count),
        });
        raw_score -= 5;
    }

    // Check for minified files (heuristic: .min.js or very long lines)
    let has_minified = walkdir::WalkDir::new(package_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .any(|e| {
            let path = e.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && (name.ends_with(".min.js") || name.ends_with(".min.cjs"))
            {
                return true;
            }
            false
        });

    if !has_minified {
        factors.push(ScoreFactor {
            name: "readable_source".into(),
            weight: 5,
            description: "All source is readable (no minified files)".into(),
        });
        raw_score += 5;
    }

    // TypeScript types
    let has_types = package_dir.join("index.d.ts").exists()
        || walkdir::WalkDir::new(package_dir)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext == "d.ts")
                    .unwrap_or(false)
                    || e.path()
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.ends_with(".d.ts"))
                        .unwrap_or(false)
            });

    if has_types {
        factors.push(ScoreFactor {
            name: "typescript_types".into(),
            weight: 5,
            description: "Has TypeScript type definitions".into(),
        });
        raw_score += 5;
    }

    // LICENSE file
    let has_license = package_dir.join("LICENSE").exists()
        || package_dir.join("LICENSE.md").exists()
        || package_dir.join("LICENSE.txt").exists()
        || package_dir.join("LICENCE").exists()
        || package_dir.join("license").exists();

    if has_license {
        factors.push(ScoreFactor {
            name: "has_license".into(),
            weight: 5,
            description: "Has LICENSE file".into(),
        });
        raw_score += 5;
    }

    // Test directory
    let has_tests = package_dir.join("test").exists()
        || package_dir.join("tests").exists()
        || package_dir.join("__tests__").exists();

    if has_tests {
        factors.push(ScoreFactor {
            name: "has_tests".into(),
            weight: 5,
            description: "Has test directory".into(),
        });
        raw_score += 5;
    }

    // Clamp to 0-100
    let final_score = raw_score.clamp(0, 100) as u8;
    let grade = score_to_grade(final_score);

    SafetyScore {
        score: final_score,
        grade,
        factors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Capabilities, Finding, FindingKind, RiskLevel};
    use std::path::PathBuf;

    fn empty_report() -> AnalysisReport {
        AnalysisReport {
            package_name: "test-pkg".into(),
            package_version: "1.0.0".into(),
            overall_risk: RiskLevel::Clean,
            findings: vec![],
            files_scanned: 1,
            lines_scanned: 10,
            capabilities: Capabilities::default(),
            verdict_reasons: vec![],
        }
    }

    #[test]
    fn clean_package_gets_high_score() {
        let report = empty_report();
        let dir = PathBuf::from("/tmp/nonexistent-test-pkg");
        let result = compute_safety_score(&report, &dir);
        // No README, no license, no tests -> penalties, but no findings
        assert!(result.score >= 60);
    }

    #[test]
    fn critical_finding_drops_score() {
        let mut report = empty_report();
        report.findings.push(Finding {
            kind: FindingKind::DataExfiltration,
            risk: RiskLevel::Critical,
            message: "sends data to remote".into(),
            file: "index.js".into(),
            line: 1,
            snippet: None,
        });
        let dir = PathBuf::from("/tmp/nonexistent-test-pkg");
        let result = compute_safety_score(&report, &dir);
        assert!(result.score <= 75);
    }
}
