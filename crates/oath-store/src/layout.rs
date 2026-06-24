//! Node modules layout types
//!
//! Describes the target layout strategy for node_modules.

/// Layout strategy for node_modules
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum NodeModulesLayout {
    /// pnpm-style: strict, symlinked, no phantom deps
    /// node_modules/.oath/{name}@{version}/node_modules/{name}
    /// node_modules/{name} -> symlink to above
    #[default]
    Strict,

    /// npm-style: flat hoisted (for compatibility with tools that don't handle symlinks)
    /// node_modules/{name}/ (all deps hoisted to top)
    Hoisted,
}

impl NodeModulesLayout {
    pub fn description(&self) -> &'static str {
        match self {
            Self::Strict => "strict (pnpm-style, no phantom deps)",
            Self::Hoisted => "hoisted (npm-style, flat)",
        }
    }
}
