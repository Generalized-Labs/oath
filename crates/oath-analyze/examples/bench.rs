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
use std::path::{Path, PathBuf};

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

fn scan_corpus(root: &Path) -> Vec<(String, RiskLevel)> {
    let mut dirs = Vec::new();
    find_package_dirs(root, &mut dirs);
    let mut results = Vec::new();
    for d in &dirs {
        let name = d
            .strip_prefix(root)
            .unwrap_or(d)
            .to_string_lossy()
            .to_string();
        if let Ok(r) = PackageScanner::scan(&name, "0.0.0", d) {
            results.push((name, r.overall_risk))
        }
    }
    results
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
    if args.len() < 3 {
        eprintln!("usage: bench <benign_root> <malware_root>");
        std::process::exit(2);
    }
    let benign = scan_corpus(Path::new(&args[1]));
    let malware = scan_corpus(Path::new(&args[2]));

    // Benign: every flag is a false positive -- show them all.
    let (b_total, b_flag) = report("BENIGN (false positives)", &benign, true);
    // Malware: flags are true positives; show the MISSES (false negatives).
    let (m_total, m_flag) = report("MALWARE (recall)", &malware, false);
    let missed: Vec<&(String, RiskLevel)> = malware
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
}
