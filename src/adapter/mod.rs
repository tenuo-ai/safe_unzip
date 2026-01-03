//! Archive format adapters.
//!
//! Adapters normalize different archive formats into a common interface
//! for the extraction engine.

#[cfg(feature = "tar")]
mod tar_adapter;
mod zip_adapter;

#[cfg(feature = "sevenz")]
mod sevenz_adapter;

#[cfg(feature = "tar")]
pub use tar_adapter::{copy_limited, TarAdapter};
pub use zip_adapter::ZipAdapter;

#[cfg(feature = "sevenz")]
pub use sevenz_adapter::SevenZAdapter;
