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

/// Compute a safety score for a package based on analysis results and package directory contents.
pub fn compute_safety_score(report: &AnalysisReport, package_dir: &Path) -> SafetyScore {
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

    // Capability-based penalties
    if report.capabilities.has_install_scripts {
        factors.push(ScoreFactor {
            name: "install_scripts".into(),
            weight: -10,
            description: "Package has install scripts".into(),
        });
        raw_score -= 10;
    }

    if report.capabilities.network && report.capabilities.env_access {
        factors.push(ScoreFactor {
            name: "network_env_combo".into(),
            weight: -20,
            description: "Network access combined with environment variable access".into(),
        });
        raw_score -= 20;
    }

    if report.capabilities.dynamic_exec {
        factors.push(ScoreFactor {
            name: "dynamic_exec".into(),
            weight: -10,
            description: "Uses dynamic code execution (eval/Function)".into(),
        });
        raw_score -= 10;
    }

    // Check for HIGH/CRITICAL obfuscation findings only (Medium ones are often false positives)
    let high_obfuscation = report
        .findings
        .iter()
        .any(|f| f.kind == FindingKind::Obfuscation && matches!(f.risk, RiskLevel::High | RiskLevel::Critical));
    if high_obfuscation {
        factors.push(ScoreFactor {
            name: "obfuscated_code".into(),
            weight: -25,
            description: "Obfuscated code detected".into(),
        });
        raw_score -= 25;
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
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".min.js") || name.ends_with(".min.cjs") {
                    return true;
                }
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
