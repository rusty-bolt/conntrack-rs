//! # Result
//! This module contains the result alias and a module reimport for the error types.

pub use crate::error::Error;

/// Result is an alias for `core::result::Result<T, conntrack::error::Error>`
pub type Result<T> = core::result::Result<T, Error>;
