//! # Connection
//! This module contains the general API for the conntrack library.

use neli::{
    consts::{nl::*, socket::*},
    genl::Genlmsghdr,
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    types::{Buffer, GenlBuffer},
};

use crate::attributes::*;
use crate::decoders::*;
use crate::message::*;
use crate::model::*;
use crate::result::*;

/// The `Conntrack` type is used to connect to a netfilter socket and execute
/// conntrack table specific commands.
pub struct Conntrack {
    socket: NlSocketHandle,
}

impl Conntrack {
    /// This method opens a netfilter socket using a `socket()` syscall, and
    /// returns the `Conntrack` instance on success.
    pub fn connect() -> Result<Self> {
        let socket = NlSocketHandle::connect(NlFamily::Netfilter, Some(0), &[])?;
        Ok(Self { socket })
    }

    /// The dump call will list all connection tracking for the `Conntrack` table as a
    /// `Vec<Flow>` instances.
    pub fn dump(&mut self) -> Result<Vec<Flow>> {
        let genlhdr = Genlmsghdr::new(
            0u8,
            libc::NFNETLINK_V0 as u8,
            GenlBuffer::<ConntrackAttr, Buffer>::new(),
        );

        self.socket.send({
            let len = None;
            let seq = None;
            let pid = None;

            let nl_type = CtNetlinkMessage::Conntrack;
            let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
            let payload = NlPayload::Payload(genlhdr);

            Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
        })?;

        let mut flows = Vec::new();
        for response in self
            .socket
            .iter::<CtNetlinkMessage, Genlmsghdr<u8, ConntrackAttr>>(false)
        {
            let result: Nlmsghdr<CtNetlinkMessage, Genlmsghdr<u8, ConntrackAttr>> = response?;
            if let Some(message) = result.nl_payload.get_payload() {
                let handle = message.get_attr_handle();

                flows.push(Flow::decode(handle)?);
            }
        }

        Ok(flows)
    }
}
