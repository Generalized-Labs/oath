//! oath-fetch: npm registry client
//!
//! Fetches packuments, resolves versions, downloads and verifies tarballs.
//! Fully compatible with the npm registry HTTP protocol.

pub mod client;
pub mod packument;
pub mod resolve;
pub mod tarball;
pub mod cache;
pub mod metadata;

pub use metadata::{PackageMetadata, Maintainer, fetch_package_metadata};

pub use client::RegistryClient;
pub use packument::{Packument, VersionInfo, DistInfo};
pub use resolve::resolve_version;
