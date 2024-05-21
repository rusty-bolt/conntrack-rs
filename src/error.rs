//! # Error
//! This module contains all the potential error types that can come from
//! the `conntrack` library.

use std::fmt::{Debug, Display};

/// Error consolidates and propagates all underlying error types.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("netlink error: {0}")]
    Netlink(String),

    #[error(transparent)]
    Socket(#[from] neli::err::SocketError),

    #[error(transparent)]
    AttrTypeBuilder(#[from] neli::genl::AttrTypeBuilderError),

    #[error(transparent)]
    GenlmsghdrBuilder(#[from] neli::genl::GenlmsghdrBuilderError),

    #[error(transparent)]
    NlattrBuilder(#[from] neli::genl::NlattrBuilderError),

    #[error(transparent)]
    NlmsghdrBuilder(#[from] neli::nl::NlmsghdrBuilderError),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    Deserialization(#[from] neli::err::DeError),

    #[error(transparent)]
    Serialization(#[from] neli::err::SerError),
}

impl<M: Debug> From<neli::err::Nlmsgerr<M>> for Error {
    fn from(value: neli::err::Nlmsgerr<M>) -> Self {
        Self::Netlink(format!("{:?}", value))
    }
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum DirFilterBuilderError {
    MissingRequiredParameter {
        parameter: &'static str,
        reason: Option<&'static str>,
    },
    InvalidParameter {
        parameter: &'static str,
        reason: &'static str,
    },
}

impl Display for DirFilterBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirFilterBuilderError::MissingRequiredParameter { parameter, reason } => {
                f.write_fmt(format_args!("missing required parameter: {parameter}"))?;
                if let Some(reason) = reason {
                    f.write_fmt(format_args!(", reason: {reason}"))?;
                }
            }
            DirFilterBuilderError::InvalidParameter { parameter, reason } => {
                f.write_fmt(format_args!(
                    "invalid parameter: {parameter}, reason: {reason}"
                ))?;
            }
        }
        Ok(())
    }
}
