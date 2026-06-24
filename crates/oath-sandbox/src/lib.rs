//! oath-sandbox: permission-gated execution for package scripts and oathx
//!
//! Two modes:
//! 1. OS sandbox (macOS sandbox-exec, Linux landlock) — for Node scripts that need
//!    real I/O but should be restricted to declared permissions
//! 2. Deny-by-default — block network, limit fs to project dir, no env leakage
//!
//! This is what makes `oathx` safe: you run arbitrary package binaries but they
//! can only touch what you explicitly allow.

pub mod executor;
pub mod linux;
pub mod macos;
pub mod policy;

pub use executor::{ExecResult, SandboxExecutor};
pub use policy::{Permission, SandboxPolicy};
