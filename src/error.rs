//! Conntrack Error 

use std::fmt::Debug;

/// Error consolidates and propagates all underlying error types. 
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("netlink error: {0}")]
    Netlink(String),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    Deserialization(#[from] neli::err::DeError),

    #[error(transparent)]
    Serialization(#[from] neli::err::SerError),
}

impl<T: Debug, P: Debug> From<neli::err::NlError<T, P>> for Error {
    fn from(value: neli::err::NlError<T, P>) -> Self {
        Self::Netlink(format!("{:?}", value))
    }
}