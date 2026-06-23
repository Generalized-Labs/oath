//! oath-sandbox: permission-gated execution for package scripts and oathx
//!
//! Two modes:
//! 1. OS sandbox (macOS sandbox-exec, Linux landlock) — for Node scripts that need
//!    real I/O but should be restricted to declared permissions
//! 2. Deny-by-default — block network, limit fs to project dir, no env leakage
//!
//! This is what makes `oathx` safe: you run arbitrary package binaries but they
//! can only touch what you explicitly allow.

pub mod policy;
pub mod executor;
pub mod macos;
pub mod linux;

pub use policy::{SandboxPolicy, Permission};
pub use executor::{SandboxExecutor, ExecResult};
