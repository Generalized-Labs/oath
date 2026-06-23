//! oath-store: content-addressable package store
//!
//! Global store at ~/.oath/store/ keyed by content hash (BLAKE3).
//! Projects link packages from the store via hardlinks (saving disk space).
//! Layout: pnpm-inspired strict node_modules (no phantom deps).

pub mod cas;
pub mod linker;
pub mod layout;

pub use cas::ContentStore;
pub use linker::Linker;
pub use layout::NodeModulesLayout;
