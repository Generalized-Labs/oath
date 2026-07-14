//! Scanner benchmark: measure false-positive rate (benign corpus) and recall
//! (malware corpus). STATIC ANALYSIS ONLY -- no sample is ever executed.
//!
//! Usage:
//!   cargo run --release -p oath-analyze --example bench -- <benign_root> <malware_root>
//!
//! A "package dir" is any directory directly containing a package.json (nested
//! node_modules are skipped). Each is scanned with PackageScanner::scan; a result
//! of High or Critical counts as "flagged". On the benign set that's a false
//! positive; on the malware set it's a true positive.

use oath_analyze::{PackageScanner, RiskLevel};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct CorpusResult {
    discovered: usize,
    scanned: Vec<(String, RiskLevel)>,
    errors: Vec<(String, String)>,
}

fn find_package_dirs(root: &Path, out: &mut Vec<PathBuf>) {
    let rd = match std::fs::read_dir(root) {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut has_pkg = false;
    let mut subdirs = Vec::new();
    for e in rd.flatten() {
        let ft = match e.file_type() {
            Ok(f) => f,
            Err(_) => continue,
        };
        if ft.is_file() && e.file_name() == "package.json" {
            has_pkg = true;
        } else if ft.is_dir() && e.file_name() != "node_modules" {
            subdirs.push(e.path());
        }
    }
    if has_pkg {
        out.push(root.to_path_buf());
    }
    for d in subdirs {
        find_package_dirs(&d, out);
    }
}

fn scan_corpus(root: &Path) -> CorpusResult {
    let mut dirs = Vec::new();
    find_package_dirs(root, &mut dirs);
    let mut results = Vec::new();
    let mut errors = Vec::new();
    for d in &dirs {
        let name = d
            .strip_prefix(root)
            .unwrap_or(d)
            .to_string_lossy()
            .to_string();
        match PackageScanner::scan(&name, "0.0.0", d) {
            Ok(report) => results.push((name, report.overall_risk)),
            Err(error) => errors.push((name, error.to_string())),
        }
    }
    CorpusResult {
        discovered: dirs.len(),
        scanned: results,
        errors,
    }
}

fn wilson(successes: usize, total: usize) -> (f64, f64) {
    if total == 0 {
        return (0.0, 1.0);
    }
    let z = 1.959_963_984_540_054_f64;
    let n = total as f64;
    let p = successes as f64 / n;
    let denominator = 1.0 + z * z / n;
    let center = (p + z * z / (2.0 * n)) / denominator;
    let margin = z * ((p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt()) / denominator;
    ((center - margin).max(0.0), (center + margin).min(1.0))
}

fn report(label: &str, results: &[(String, RiskLevel)], show_flagged: bool) -> (usize, usize) {
    let total = results.len();
    let mut flagged: Vec<&(String, RiskLevel)> = results
        .iter()
        .filter(|(_, r)| *r >= RiskLevel::High)
        .collect();
    flagged.sort_by(|a, b| b.1.cmp(&a.1));
    let n = flagged.len();
    println!(
        "\n=== {label}: {total} packages, {n} flagged (High/Critical) = {:.1}% ===",
        100.0 * n as f64 / total.max(1) as f64
    );
    if show_flagged {
        for (name, r) in flagged.iter().take(50) {
            println!("    [{:?}] {}", r, name);
        }
        if flagged.len() > 50 {
            println!("    ... and {} more", flagged.len() - 50);
        }
    }
    (total, n)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json_output = args.iter().any(|arg| arg == "--json");
    let roots = args
        .iter()
        .skip(1)
        .filter(|arg| arg.as_str() != "--json")
        .collect::<Vec<_>>();
    if roots.len() != 2 {
        eprintln!("usage: bench [--json] <benign_root> <malware_root>");
        std::process::exit(2);
    }
    let benign = scan_corpus(Path::new(roots[0]));
    let malware = scan_corpus(Path::new(roots[1]));

    let b_total = benign.scanned.len();
    let b_flag = benign
        .scanned
        .iter()
        .filter(|(_, risk)| *risk >= RiskLevel::High)
        .count();
    let m_total = malware.scanned.len();
    let m_flag = malware
        .scanned
        .iter()
        .filter(|(_, risk)| *risk >= RiskLevel::High)
        .count();
    let fp_ci = wilson(b_flag, b_total);
    let recall_ci = wilson(m_flag, m_total);
    let gate_passes = malware.errors.is_empty()
        && benign.errors.is_empty()
        && m_total > 0
        && b_total > 0
        && (m_flag as f64 / m_total as f64) >= 0.99
        && (b_flag as f64 / b_total as f64) <= 0.005;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "evidence_class": "scanner-corpus",
                "threshold": "HIGH_OR_CRITICAL",
                "benign": {
                    "discovered": benign.discovered,
                    "scanned": b_total,
                    "scan_errors": benign.errors,
                    "false_positives": b_flag,
                    "false_positive_rate": b_flag as f64 / b_total.max(1) as f64,
                    "wilson_95": {"lower": fp_ci.0, "upper": fp_ci.1},
                },
                "malware": {
                    "discovered": malware.discovered,
                    "scanned": m_total,
                    "scan_errors": malware.errors,
                    "detected": m_flag,
                    "recall": m_flag as f64 / m_total.max(1) as f64,
                    "wilson_95": {"lower": recall_ci.0, "upper": recall_ci.1},
                },
                "ga_gate": {
                    "known_malware_recall_target": 0.99,
                    "benign_false_positive_target": 0.005,
                    "passes": gate_passes,
                }
            }))
            .unwrap()
        );
        if !gate_passes {
            std::process::exit(1);
        }
        return;
    }

    // Benign: every flag is a false positive -- show them all.
    let (b_total, b_flag) = report("BENIGN (false positives)", &benign.scanned, true);
    // Malware: flags are true positives; show the MISSES (false negatives).
    let (m_total, m_flag) = report("MALWARE (recall)", &malware.scanned, false);
    let missed: Vec<&(String, RiskLevel)> = malware
        .scanned
        .iter()
        .filter(|(_, r)| *r < RiskLevel::High)
        .collect();
    println!("\n  MALWARE false negatives (missed): {}", missed.len());
    for (name, r) in missed.iter().take(40) {
        println!("    [{:?}] {}", r, name);
    }
    if missed.len() > 40 {
        println!("    ... and {} more", missed.len() - 40);
    }
    println!(
        "  Scan errors: benign={}, malware={}",
        benign.errors.len(),
        malware.errors.len()
    );

    println!("\n================ SUMMARY ================");
    println!(
        "  FP rate (benign):   {:>5.1}%   ({}/{})",
        100.0 * b_flag as f64 / b_total.max(1) as f64,
        b_flag,
        b_total
    );
    println!(
        "  Recall (malware):   {:>5.1}%   ({}/{})",
        100.0 * m_flag as f64 / m_total.max(1) as f64,
        m_flag,
        m_total
    );
    if !gate_passes {
        std::process::exit(1);
    }
}
