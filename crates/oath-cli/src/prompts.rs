//! Interactive prompts for the oath CLI.

use std::io::{self, Write};

use oath_analyze::Capabilities;
use oath_core::policy::OathPolicy;

/// Result of the install-script prompt
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptDecision {
    /// Allow this script to run normally
    Allow,
    /// Allow but run inside the sandbox executor
    Sandbox,
    /// Always allow (appended to local policy allowlist)
    Always,
    /// Deny -- do not run the script
    Deny,
}

/// Format capabilities for display in the prompt.
fn fmt_caps(caps: &Capabilities) -> String {
    let mut parts = vec![];
    if caps.network {
        parts.push("network");
    }
    if caps.filesystem {
        parts.push("filesystem");
    }
    if caps.env_access {
        parts.push("env");
    }
    if caps.subprocess {
        parts.push("subprocess");
    }
    if caps.dynamic_exec {
        parts.push("eval/dynamic");
    }
    if parts.is_empty() {
        "none detected".to_string()
    } else {
        parts.join(", ")
    }
}

/// Prompt the user about a detected postinstall script.
///
/// Prints:
///   oath: postinstall script detected
///   package: esbuild@0.21.5
///   script:  node install.js
///   wants:   network, filesystem
///
///   Allow? [y/N/s(andbox)/a(lways)]
///
/// Returns the user's decision.
///
/// When `yes_flag` is true (--yes passed), returns `ScriptDecision::Allow` without prompting.
/// When the package is pre-approved by policy, returns `ScriptDecision::Allow` without prompting.
pub fn prompt_install_script(
    package_name: &str,
    version: &str,
    script: &str,
    capabilities: &Capabilities,
    yes_flag: bool,
    policy: &OathPolicy,
) -> ScriptDecision {
    // Policy pre-approves
    if policy.allows_install_script(package_name) {
        return ScriptDecision::Allow;
    }

    // --yes flag
    if yes_flag {
        return ScriptDecision::Allow;
    }

    println!();
    println!("  oath: postinstall script detected");
    println!("  package: {package_name}@{version}");
    println!("  script:  {script}");
    println!("  wants:   {}", fmt_caps(capabilities));
    println!();

    loop {
        print!("  Allow? [y/N/s(andbox)/a(lways)] ");
        io::stdout().flush().unwrap_or(());

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(0) => {
                // EOF -- deny by default
                println!();
                return ScriptDecision::Deny;
            }
            Err(_) => return ScriptDecision::Deny,
            Ok(_) => {}
        }

        let answer = input.trim().to_lowercase();
        match answer.as_str() {
            "y" | "yes" => return ScriptDecision::Allow,
            "" | "n" | "no" => return ScriptDecision::Deny,
            "s" | "sandbox" => return ScriptDecision::Sandbox,
            "a" | "always" => {
                append_to_policy_allowlist(package_name);
                return ScriptDecision::Always;
            }
            _ => {
                println!("  Please enter y, N, s, or a.");
            }
        }
    }
}

/// Append a package to the local oath-policy.toml allow_install_scripts list.
/// Creates the file if it doesn't exist.
fn append_to_policy_allowlist(package_name: &str) {
    let path = std::path::PathBuf::from("oath-policy.toml");

    // Read existing content
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    // Check if it's already in there
    if existing.contains(&format!("\"{package_name}\"")) {
        return;
    }

    // Parse and amend. Simple approach: append a new allow_install_scripts entry
    // or update the existing array.
    let new_content = if existing.is_empty() {
        // Create minimal file
        format!(
            "# oath-policy.toml -- auto-generated\nallow_install_scripts = [\"{package_name}\"]\n"
        )
    } else if let Some(start) = existing.find("allow_install_scripts") {
        // Find the closing bracket and insert before it
        if let Some(bracket_pos) = existing[start..].find(']') {
            let insert_at = start + bracket_pos;
            let before = &existing[..insert_at];
            let after = &existing[insert_at..];
            // Add comma if there are existing entries
            let trimmed = before.trim_end();
            let sep = if trimmed.ends_with('[') { "" } else { ", " };
            format!("{trimmed}{sep}\"{package_name}\"{after}")
        } else {
            // Malformed -- just append
            format!("{existing}\n# added by oath\nallow_install_scripts = [\"{package_name}\"]\n")
        }
    } else {
        // No existing key -- append
        format!("{existing}\nallow_install_scripts = [\"{package_name}\"]\n")
    };

    if let Err(e) = std::fs::write(&path, &new_content) {
        eprintln!("oath: warning: could not update oath-policy.toml: {e}");
    } else {
        println!("  oath: added {package_name} to oath-policy.toml allow_install_scripts");
    }
}
