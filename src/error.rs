//! # Error
//! This module contains all the potential error types that can come from
//! the `conntrack` library.

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

    #[error(transparent)]
    Socket(#[from] neli::err::SocketError),

    #[error(transparent)]
    GenlBuilder(#[from] neli::genl::GenlmsghdrBuilderError),

    #[error(transparent)]
    NlBuilder(#[from] neli::nl::NlmsghdrBuilderError),
}

impl<T: Debug, P: Debug> From<neli::err::RouterError<T, P>> for Error {
    fn from(value: neli::err::RouterError<T, P>) -> Self {
        Self::Netlink(format!("{value:?}"))
    }
}
