//! OS sandbox integration hooks.
//!
//! The executor currently provides the portable safety baseline used by tests:
//! environment stripping, cwd isolation, and timeouts. Kernel policy enforcement
//! for macOS Seatbelt and Linux Landlock belongs behind this crate boundary.

pub mod executor;
pub mod policy;

/// Returns whether this platform is in scope for OS-level sandboxing.
pub fn platform_supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "linux"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_supported_launch_platforms() {
        assert_eq!(
            platform_supported(),
            cfg!(any(target_os = "macos", target_os = "linux"))
        );
    }
}
