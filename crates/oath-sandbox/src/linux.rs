//! Linux sandbox via Landlock (kernel 5.13+)
//!
//! Fallback: seccomp-bpf if landlock unavailable.
//! For now, just the policy translation -- actual landlock FFI is TODO
//! until we test on Linux.

use crate::policy::SandboxPolicy;

/// Check if Landlock is available on this kernel
pub fn is_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::path::Path;
        Path::new("/sys/kernel/security/landlock").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Build landlock rules from policy (Linux-only, no-op on other platforms)
pub fn apply_landlock(_policy: &SandboxPolicy) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        // TODO: actual landlock_create_ruleset / landlock_add_rule / landlock_restrict_self
        // via syscall. For now we rely on the macOS sandbox-exec path.
        Err("landlock implementation pending".to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("landlock only available on Linux".to_string())
    }
}
