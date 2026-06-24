//! oath-analyze: static analysis engine for npm packages
//!
//! Parses JS/TS source with OXC and detects what system resources
//! each package actually accesses -- network, fs, subprocess, env,
//! dynamic code execution, obfuscation.

pub mod analyzer;
pub mod behavior;
pub mod patterns;
pub mod report;
pub mod scanner;
pub mod score;

pub use analyzer::Analyzer;
pub use behavior::{Behavior, Verdict};
pub use report::{AnalysisReport, Capabilities, Finding, FindingKind, RiskLevel, PackageRisk};
pub use scanner::PackageScanner;
pub use score::{SafetyScore, ScoreFactor, compute_safety_score};
