//! # Connection
//! This module contains the general API for the conntrack library.

use neli::{
    consts::{nl::*, socket::*},
    genl::{Genlmsghdr, GenlmsghdrBuilder},
    nl::{NlPayload, Nlmsghdr, NlmsghdrBuilder},
    socket::synchronous::NlSocketHandle,
    types::{Buffer, GenlBuffer},
    utils::Groups,
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
        let socket = NlSocketHandle::connect(NlFamily::Netfilter, Some(0), Groups::empty())?;
        Ok(Self { socket })
    }

    /// The dump call will list all connection tracking for the `Conntrack` table as a
    /// `Vec<Flow>` instances.
    pub fn dump(&mut self) -> Result<Vec<Flow>> {
        let genlhdr = GenlmsghdrBuilder::default()
            .cmd(0u8)
            .version(libc::NFNETLINK_V0 as u8)
            .attrs(GenlBuffer::<ConntrackAttr, Buffer>::new())
            .build()?;

        let msg = NlmsghdrBuilder::default()
            .nl_type(CtNetlinkMessage::Conntrack)
            .nl_flags(NlmF::REQUEST | NlmF::DUMP)
            .nl_payload(NlPayload::Payload(genlhdr))
            .build()?;

        self.socket.send(&msg)?;

        let mut flows = Vec::new();
        let (recv_iter, _) = self
            .socket
            .recv::<CtNetlinkMessage, Genlmsghdr<u8, ConntrackAttr>>()?;

        for result in recv_iter {
            let result: Nlmsghdr<CtNetlinkMessage, Genlmsghdr<u8, ConntrackAttr>> = result?;
            if let NlPayload::Payload(message) = result.nl_payload() {
                let handle = message.attrs().get_attr_handle();

                flows.push(Flow::decode(handle)?);
            }
        }

        Ok(flows)
    }
}
