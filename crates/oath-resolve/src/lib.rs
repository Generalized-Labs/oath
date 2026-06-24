//! oath-resolve: dependency graph resolution
//!
//! Takes a package.json (or direct dependency list) and produces a complete
//! dependency graph with exact resolved versions and integrity hashes.
//!
//! Uses a simple BFS resolution strategy with deduplication (hoisting).
//! Future: upgrade to PubGrub for better conflict resolution.

pub mod graph;
pub mod git;
pub mod lockfile;
pub mod resolver;

pub use graph::{DepGraph, DepNode};
pub use lockfile::Lockfile;
pub use resolver::Resolver;
