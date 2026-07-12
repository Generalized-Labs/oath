//! OS sandbox integration hooks.
//!
//! The executor currently provides the portable safety baseline used by tests:
//! environment stripping, cwd isolation, and timeouts. Kernel policy enforcement
//! for macOS Seatbelt and Linux Landlock belongs behind this crate boundary.

pub mod executor;
pub mod policy;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;

pub use policy::{NetworkMode, ResourceLimits, SANDBOX_PLAN_VERSION, SandboxPlan};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackendCapabilities {
    pub backend: String,
    pub available: bool,
    pub filesystem_isolation: bool,
    pub network_isolation: bool,
    pub process_isolation: bool,
    pub resource_limits: bool,
    pub degraded_reason: Option<String>,
}

pub fn native_capabilities() -> BackendCapabilities {
    #[cfg(target_os = "linux")]
    {
        linux::capabilities()
    }
    #[cfg(target_os = "windows")]
    {
        windows::capabilities()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        BackendCapabilities {
            backend: "unavailable".into(),
            available: false,
            filesystem_isolation: false,
            network_isolation: false,
            process_isolation: false,
            resource_limits: false,
            degraded_reason: Some("no native sandbox backend for this platform".into()),
        }
    }
}

/// Proves the advertised native controls by executing a minimal strict plan.
/// Release evidence must use this function; tool presence alone is not proof.
pub fn verified_native_capabilities() -> BackendCapabilities {
    let mut capabilities = native_capabilities();
    if !capabilities.available {
        return capabilities;
    }
    let root = match tempfile::tempdir() {
        Ok(root) => root,
        Err(error) => {
            capabilities.available = false;
            capabilities.degraded_reason = Some(format!("sandbox probe setup failed: {error}"));
            return capabilities;
        }
    };
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let _ = &root;
    #[cfg(target_os = "linux")]
    let result = {
        let plan = SandboxPlan::strict("oath-capability-probe", root.path().to_path_buf());
        linux::run(&plan, std::path::Path::new("/bin/true"), &[])
    };
    #[cfg(target_os = "windows")]
    let result = {
        let plan = SandboxPlan::strict("oath-capability-probe", root.path().to_path_buf());
        windows::run(
            &plan,
            std::path::Path::new("C:\\Windows\\System32\\cmd.exe"),
            &["/C".into(), "exit 0".into()],
        )
    };
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let result: anyhow::Result<std::process::ExitStatus> =
        Err(anyhow::anyhow!("unsupported platform"));
    match result {
        Ok(status) if status.success() => capabilities,
        Ok(status) => {
            capabilities.available = false;
            capabilities.filesystem_isolation = false;
            capabilities.network_isolation = false;
            capabilities.process_isolation = false;
            capabilities.resource_limits = false;
            capabilities.degraded_reason =
                Some(format!("native sandbox probe exited with {status}"));
            capabilities
        }
        Err(error) => {
            capabilities.available = false;
            capabilities.filesystem_isolation = false;
            capabilities.network_isolation = false;
            capabilities.process_isolation = false;
            capabilities.resource_limits = false;
            capabilities.degraded_reason = Some(format!("native sandbox probe failed: {error:#}"));
            capabilities
        }
    }
}

/// Returns whether this platform is in scope for OS-level sandboxing.
pub fn platform_supported() -> bool {
    cfg!(any(target_os = "windows", target_os = "linux"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_supported_launch_platforms() {
        assert_eq!(
            platform_supported(),
            cfg!(any(target_os = "windows", target_os = "linux"))
        );
    }
}
