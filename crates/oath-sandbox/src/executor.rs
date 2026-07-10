use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};

use crate::policy::SandboxPolicy;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub struct SandboxExecutor;

impl SandboxExecutor {
    pub fn run(command: &Path, args: &[&str], policy: &SandboxPolicy) -> Result<SandboxResult> {
        let envs = policy
            .allowed_env_names()
            .into_iter()
            .filter_map(|name| std::env::var(&name).ok().map(|value| (name, value)))
            .collect::<Vec<_>>();
        run_with_env(command, args, policy, &envs)
    }
}

fn run_with_env(
    command: &Path,
    args: &[&str],
    policy: &SandboxPolicy,
    envs: &[(String, String)],
) -> Result<SandboxResult> {
    let mut child = Command::new(command)
        .args(args)
        .current_dir(&policy.workdir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .envs(envs.iter().map(|(name, value)| (name, value)))
        .spawn()
        .with_context(|| format!("failed to spawn {}", command.display()))?;

    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            let output = child.wait_with_output()?;
            return Ok(SandboxResult {
                exit_code: output.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }
        if started.elapsed() > Duration::from_secs(policy.timeout_secs) {
            child.kill().ok();
            child.wait().ok();
            return Err(anyhow!(
                "sandboxed command timed out after {}s",
                policy.timeout_secs
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
