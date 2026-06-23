//! Sandbox executor: run package scripts/binaries with permission enforcement
//!
//! On macOS: uses sandbox-exec (Seatbelt)
//! On Linux: will use Landlock + seccomp (TODO)
//! Fallback: env stripping + timeout (weaker but portable)

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::policy::{Permission, SandboxPolicy};

/// Result of a sandboxed execution
#[derive(Debug)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
    pub sandbox_method: SandboxMethod,
}

/// Which sandboxing mechanism was used
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SandboxMethod {
    /// macOS sandbox-exec (Seatbelt)
    MacosSeatbelt,
    /// Linux Landlock
    LinuxLandlock,
    /// Fallback: env stripping + timeout only
    Fallback,
    /// No sandbox (--allow-all)
    None,
}

/// Execute a command under the given sandbox policy
pub struct SandboxExecutor;

impl SandboxExecutor {
    /// Run a binary with sandbox restrictions
    ///
    /// `binary` - path to the executable (usually node or the package bin)
    /// `args` - arguments to pass
    /// `policy` - the sandbox policy defining what's allowed
    pub fn run(
        binary: &Path,
        args: &[&str],
        policy: &SandboxPolicy,
    ) -> Result<ExecResult> {
        // If unrestricted, just run directly
        if policy.permissions.iter().any(|p| matches!(p, Permission::Unrestricted)) {
            return Self::run_unrestricted(binary, args, policy);
        }

        // Pick sandbox method
        if crate::macos::is_available() {
            Self::run_macos(binary, args, policy)
        } else if crate::linux::is_available() {
            Self::run_linux(binary, args, policy)
        } else {
            Self::run_fallback(binary, args, policy)
        }
    }

    /// Run a Node.js package script (from package.json "scripts")
    pub fn run_script(
        script_cmd: &str,
        policy: &SandboxPolicy,
    ) -> Result<ExecResult> {
        let node = find_node()?;
        // Run via shell but sandboxed
        let shell_args = vec!["-c", script_cmd];

        if crate::macos::is_available()
            && !policy.permissions.iter().any(|p| matches!(p, Permission::Unrestricted))
        {
            Self::run_macos(Path::new("/bin/sh"), &shell_args, policy)
        } else {
            Self::run_fallback(Path::new("/bin/sh"), &shell_args, policy)
        }
    }

    /// Run an oathx package binary
    ///
    /// Resolves the binary from the package's bin field, then executes it
    /// under the sandbox with the given permissions.
    pub fn run_oathx(
        package_bin: &Path,
        args: &[&str],
        policy: &SandboxPolicy,
    ) -> Result<ExecResult> {
        let node = find_node()?;
        let mut full_args = vec![package_bin.to_str().unwrap_or("")];
        full_args.extend_from_slice(args);
        Self::run(&node, &full_args, policy)
    }

    // ---- Platform implementations ----

    fn run_macos(binary: &Path, args: &[&str], policy: &SandboxPolicy) -> Result<ExecResult> {
        let profile = policy.to_sandbox_profile();

        // Write profile to temp file
        let profile_path = std::env::temp_dir().join(format!("oath-sandbox-{}.sb", std::process::id()));
        std::fs::write(&profile_path, &profile)
            .context("failed to write sandbox profile")?;

        let start = Instant::now();

        let mut cmd = Command::new("sandbox-exec");
        cmd.arg("-f").arg(&profile_path)
            .arg(binary)
            .args(args)
            .current_dir(&policy.workdir);

        // Strip environment except allowed vars
        let env_snapshot: Vec<(String, String)> = std::env::vars().collect();
        cmd.env_clear();

        // Always pass through PATH, HOME, TMPDIR (needed for basic operation)
        let passthrough = ["PATH", "HOME", "TMPDIR", "USER", "SHELL", "LANG", "TERM"];
        for key in passthrough {
            if let Ok(val) = std::env::var(key) {
                cmd.env(key, val);
            }
        }

        // Pass through explicitly allowed env vars
        for perm in &policy.permissions {
            if let Permission::Env(names) = perm {
                if names.is_empty() {
                    // All env allowed
                    for (k, v) in &env_snapshot {
                        cmd.env(k, v);
                    }
                } else {
                    for name in names {
                        if let Ok(val) = std::env::var(name) {
                            cmd.env(name, val);
                        }
                    }
                }
            }
        }

        let output = if policy.timeout_secs > 0 {
            // Use timeout wrapper
            let child = cmd.stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .context("failed to spawn sandbox-exec")?;

            wait_with_timeout(child, Duration::from_secs(policy.timeout_secs))?
        } else {
            cmd.output().context("failed to run sandbox-exec")?
        };

        // Clean up profile
        let _ = std::fs::remove_file(&profile_path);

        Ok(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration: start.elapsed(),
            sandbox_method: SandboxMethod::MacosSeatbelt,
        })
    }

    fn run_linux(binary: &Path, args: &[&str], policy: &SandboxPolicy) -> Result<ExecResult> {
        // TODO: implement landlock
        // For now fall back
        Self::run_fallback(binary, args, policy)
    }

    fn run_fallback(binary: &Path, args: &[&str], policy: &SandboxPolicy) -> Result<ExecResult> {
        let start = Instant::now();

        let mut cmd = Command::new(binary);
        cmd.args(args)
            .current_dir(&policy.workdir);

        // Strip all env vars except basics (weak sandbox but better than nothing)
        cmd.env_clear();
        let passthrough = ["PATH", "HOME", "TMPDIR", "USER", "SHELL", "LANG", "TERM"];
        for key in passthrough {
            if let Ok(val) = std::env::var(key) {
                cmd.env(key, val);
            }
        }

        // Allowed env
        for perm in &policy.permissions {
            if let Permission::Env(names) = perm {
                for name in names {
                    if let Ok(val) = std::env::var(name) {
                        cmd.env(name, val);
                    }
                }
            }
        }

        let output = if policy.timeout_secs > 0 {
            let child = cmd.stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .context("failed to spawn process")?;
            wait_with_timeout(child, Duration::from_secs(policy.timeout_secs))?
        } else {
            cmd.output().context("failed to run process")?
        };

        Ok(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration: start.elapsed(),
            sandbox_method: SandboxMethod::Fallback,
        })
    }

    fn run_unrestricted(binary: &Path, args: &[&str], policy: &SandboxPolicy) -> Result<ExecResult> {
        let start = Instant::now();
        let output = Command::new(binary)
            .args(args)
            .current_dir(&policy.workdir)
            .output()
            .context("failed to run process")?;

        Ok(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration: start.elapsed(),
            sandbox_method: SandboxMethod::None,
        })
    }
}

/// Wait for a child process with a timeout, killing it if it exceeds
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output> {
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = child.stdout.take().map(|mut s| {
                    let mut buf = Vec::new();
                    std::io::Read::read_to_end(&mut s, &mut buf).ok();
                    buf
                }).unwrap_or_default();
                let stderr = child.stderr.take().map(|mut s| {
                    let mut buf = Vec::new();
                    std::io::Read::read_to_end(&mut s, &mut buf).ok();
                    buf
                }).unwrap_or_default();

                return Ok(std::process::Output { status, stdout, stderr });
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    anyhow::bail!("process timed out after {}s", timeout.as_secs());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Find the node binary
fn find_node() -> Result<PathBuf> {
    let output = Command::new("which")
        .arg("node")
        .output()
        .context("failed to find node")?;
    if output.status.success() {
        Ok(PathBuf::from(
            String::from_utf8_lossy(&output.stdout).trim(),
        ))
    } else {
        anyhow::bail!("node not found in PATH")
    }
}
