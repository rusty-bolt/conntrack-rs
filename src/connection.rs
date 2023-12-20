//! # Connection
//! This module contains the general API for the conntrack library.

use std::net::Ipv4Addr;

use neli::{
    consts::{nl::*, socket::*},
    genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder},
    nl::{NlPayload, Nlmsghdr},
    socket::synchronous::NlSocketHandle,
    types::{Buffer, GenlBuffer},
};

use crate::decoders::*;
use crate::message::*;
use crate::model::*;
use crate::result::*;
use crate::{attributes::*, DirFilterBuilderError};

/// The `Conntrack` type is used to connect to a netfilter socket and execute
/// conntrack table specific commands.
pub struct Conntrack {
    socket: NlSocketHandle,
    filter: Option<Filter>,
}

impl Conntrack {
    /// This method opens a netfilter socket using a `socket()` syscall, and
    /// returns the `Conntrack` instance on success.
    pub fn connect() -> Result<Self> {
        let socket =
            NlSocketHandle::connect(NlFamily::Netfilter, Some(0), neli::utils::Groups::empty())?;
        Ok(Self {
            socket,
            filter: None,
        })
    }

    pub fn filter(mut self, filter: Filter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// The dump call will list all connection tracking for the `Conntrack` table as a
    /// `Vec<Flow>` instances.
    pub fn dump(&mut self) -> Result<Vec<Flow>> {
        let attrs = self
            .filter
            .as_ref()
            .map(|x| x.attrs())
            .transpose()?
            .unwrap_or_default();
        let genlhdr = GenlmsghdrBuilder::default()
            .cmd(2u8)
            .version(libc::NFNETLINK_V0 as u8)
            .attrs(attrs)
            .build()?;

        self.socket.send({
            &neli::nl::NlmsghdrBuilder::default()
                .nl_type(CtNetlinkMessage::Conntrack)
                .nl_flags(NlmF::REQUEST | NlmF::DUMP)
                .nl_payload(NlPayload::Payload(genlhdr))
                .build()?
        })?;

        let mut flows = Vec::new();
        for response in self.socket.recv()?.0 {
            let result: Nlmsghdr<CtNetlinkMessage, Genlmsghdr<u8, ConntrackAttr>> = response?;
            if let Some(message) = result.get_payload() {
                let handle = message.attrs().get_attr_handle();

                flows.push(Flow::decode(handle)?);
            }
        }

        Ok(flows)
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct Filter {
    orig: DirFilter,
    reply: DirFilter,
}

impl Filter {
    pub fn attrs(&self) -> Result<GenlBuffer<ConntrackAttr, Buffer>> {
        let Self { orig, reply } = self;
        let mut attrs = GenlBuffer::<ConntrackAttr, Buffer>::new();
        for (attr, tuple_attrs) in [
            (ConntrackAttr::CtaTupleOrig, orig.attrs()?),
            (ConntrackAttr::CtaTupleReply, reply.attrs()?),
        ] {
            if !tuple_attrs.is_empty() {
                attrs.push(
                    NlattrBuilder::default()
                        .nla_type(
                            AttrTypeBuilder::default()
                                .nla_type(attr)
                                .nla_nested(true)
                                .build()?,
                        )
                        .nla_payload(tuple_attrs)
                        .build()?,
                );
            }
        }
        {
            let mut filter_flag_attrs = GenlBuffer::<FilterFlagAttr, Buffer>::new();
            for (attr, flags) in [
                (FilterFlagAttr::CtaFilterOrigFlags, orig.flags()),
                (FilterFlagAttr::CtaFilterReplyFlags, reply.flags()),
            ] {
                filter_flag_attrs.push(
                    NlattrBuilder::default()
                        .nla_type(AttrTypeBuilder::default().nla_type(attr).build()?)
                        .nla_payload(flags.bits())
                        .build()?,
                );
            }
            attrs.push(
                NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(ConntrackAttr::CtaFilter)
                            .nla_nested(true)
                            .build()?,
                    )
                    .nla_payload(filter_flag_attrs)
                    .build()?,
            );
        }
        Ok(attrs)
    }

    pub fn orig(&mut self, value: DirFilter) -> &mut Self {
        self.orig = value;
        self
    }

    pub fn with_orig(mut self, value: DirFilter) -> Self {
        self.orig = value;
        self
    }

    pub fn reply(&mut self, value: DirFilter) -> &mut Self {
        self.reply = value;
        self
    }

    pub fn with_reply(mut self, value: DirFilter) -> Self {
        self.reply = value;
        self
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct DirFilter {
    ipv4_src: Option<Ipv4Addr>,
    ipv4_dst: Option<Ipv4Addr>,
    l4_proto: Option<IpProto>,
    l4_src_port: Option<u16>,
    l4_dst_port: Option<u16>,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
    icmp_id: Option<u16>,
    zone: Option<u16>,
}

impl DirFilter {
    pub fn attrs(&self) -> Result<GenlBuffer<TupleAttr, Buffer>> {
        // These parameters are handled by proto_tuple_attrs
        let Self {
            ipv4_src,
            ipv4_dst,
            l4_proto: _,
            l4_src_port: _,
            l4_dst_port: _,
            icmp_type: _,
            icmp_code: _,
            icmp_id: _,
            zone,
        } = self;
        let mut attrs = GenlBuffer::<TupleAttr, Buffer>::new();
        let ip_tuple_attrs = {
            let mut attrs = GenlBuffer::<IpTupleAttr, Buffer>::new();
            if let Some(ipv4_src) = ipv4_src {
                attrs.push(
                    NlattrBuilder::default()
                        .nla_type(
                            AttrTypeBuilder::default()
                                .nla_type(IpTupleAttr::CtaIpv4Src)
                                .build()?,
                        )
                        .nla_payload(u32::from_be_bytes(ipv4_src.octets()).to_be())
                        .build()?,
                );
            }
            if let Some(ipv4_dst) = ipv4_dst {
                attrs.push(
                    NlattrBuilder::default()
                        .nla_type(
                            AttrTypeBuilder::default()
                                .nla_type(IpTupleAttr::CtaIpv4Dst)
                                .build()?,
                        )
                        .nla_payload(u32::from_be_bytes(ipv4_dst.octets()).to_be())
                        .build()?,
                );
            }
            attrs
        };
        if !ip_tuple_attrs.is_empty() {
            attrs.push(
                NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(TupleAttr::CtaTupleIp)
                            .nla_nested(true)
                            .build()?,
                    )
                    .nla_payload(ip_tuple_attrs)
                    .build()?,
            );
        }
        let proto_tuple_attrs = self.proto_tuple_attrs()?;
        if !proto_tuple_attrs.is_empty() {
            attrs.push(
                NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(TupleAttr::CtaTupleProto)
                            .nla_nested(true)
                            .build()?,
                    )
                    .nla_payload(proto_tuple_attrs)
                    .build()?,
            );
        }
        if let Some(zone) = zone {
            attrs.push(
                NlattrBuilder::default()
                    .nla_type(
                        AttrTypeBuilder::default()
                            .nla_type(TupleAttr::CtaTupleZone)
                            .build()?,
                    )
                    .nla_payload(zone.to_be())
                    .build()?,
            );
        }
        Ok(attrs)
    }

    pub fn flags(&self) -> FilterFlags {
        macro_rules! set {
            (
                &mut $flags:expr,
                $( $param:ident : $flag:ident , )*
            ) => {
                $(
                    if $param.is_some() {
                        $flags |= FilterFlags::$flag;
                    }
                )*
            };
        }
        let Self {
            ipv4_src,
            ipv4_dst,
            l4_proto,
            l4_src_port,
            l4_dst_port,
            icmp_type,
            icmp_code,
            icmp_id,
            zone,
        } = self;
        let mut flags = FilterFlags::empty();
        set! {
            &mut flags,
            ipv4_src: IpSrc,
            ipv4_dst: IpDst,
            l4_proto: ProtoNum,
            l4_src_port: ProtoSrcPort,
            l4_dst_port: ProtoDstPort,
            zone: TupleZone,
        };
        match l4_proto {
            Some(IpProto::Icmp) => {
                set! {
                    &mut flags,
                    icmp_type: ProtoIcmpType,
                    icmp_code: ProtoIcmpCode,
                    icmp_id: ProtoIcmpId,
                };
            }
            Some(IpProto::Icmpv6) => {
                set! {
                    &mut flags,
                    icmp_type: ProtoIcmpv6Type,
                    icmp_code: ProtoIcmpv6Code,
                    icmp_id: ProtoIcmpv6Id,
                };
            }
            _ => {}
        }
        flags
    }

    fn proto_tuple_attrs(&self) -> Result<GenlBuffer<ProtoTupleAttr, Buffer>> {
        macro_rules! add {
            (
                &mut $attrs:expr,
                $( ($attr:ident, $param:ident, $value:expr), )+
            ) => {
                $(
                    if let Some($param) = $param {
                        $attrs.push(
                            NlattrBuilder::default()
                                .nla_type(
                                    AttrTypeBuilder::default()
                                        .nla_type(ProtoTupleAttr::$attr)
                                        .build()?,
                                )
                                .nla_payload($value)
                                .build()?
                        );
                    }
                )*
            };
        }
        let Self {
            ipv4_src: _,
            ipv4_dst: _,
            l4_proto,
            l4_src_port,
            l4_dst_port,
            icmp_type,
            icmp_code,
            icmp_id,
            zone: _,
        } = self;
        let mut attrs = GenlBuffer::<ProtoTupleAttr, Buffer>::new();
        add!(
            &mut attrs,
            (CtaProtoNum, l4_proto, *l4_proto),
            (CtaProtoSrcPort, l4_src_port, l4_src_port.to_be()),
            (CtaProtoDstPort, l4_dst_port, l4_dst_port.to_be()),
        );
        match l4_proto {
            Some(IpProto::Icmp) => {
                add!(
                    &mut attrs,
                    (CtaProtoIcmpCode, icmp_code, *icmp_code),
                    (CtaProtoIcmpType, icmp_type, *icmp_type),
                    (CtaProtoIcmpId, icmp_id, icmp_id.to_be()),
                );
            }
            Some(IpProto::Icmpv6) => {
                add!(
                    &mut attrs,
                    (CtaProtoIcmpV6Code, icmp_code, *icmp_code),
                    (CtaProtoIcmpV6Type, icmp_type, *icmp_type),
                    (CtaProtoIcmpV6Id, icmp_id, icmp_id.to_be()),
                );
            }
            _ => {}
        };
        Ok(attrs)
    }
}

#[derive(Debug, Default)]
pub struct DirFilterBuilder {
    ipv4_src: Option<Ipv4Addr>,
    ipv4_dst: Option<Ipv4Addr>,
    l4_proto: Option<IpProto>,
    l4_src_port: Option<u16>,
    l4_dst_port: Option<u16>,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
    icmp_id: Option<u16>,
    zone: Option<u16>,
}

impl DirFilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> std::result::Result<DirFilter, DirFilterBuilderError> {
        let Self {
            ipv4_src,
            ipv4_dst,
            l4_proto,
            l4_src_port,
            l4_dst_port,
            icmp_type,
            icmp_code,
            icmp_id,
            zone,
        } = self;
        if l4_proto.is_none() {
            if l4_src_port.is_some() {
                return Err(DirFilterBuilderError::MissingRequiredParameter {
                    parameter: "l4_proto",
                    reason: Some("l4_src_port is present"),
                });
            }
            if l4_dst_port.is_some() {
                return Err(DirFilterBuilderError::MissingRequiredParameter {
                    parameter: "l4_proto",
                    reason: Some("l4_dst_port is present"),
                });
            }
        }
        if !matches!(l4_proto, Some(IpProto::Icmp | IpProto::Icmpv6)) {
            if icmp_type.is_some() {
                return Err(DirFilterBuilderError::InvalidParameter {
                    parameter: "l4_proto",
                    reason: "icmp_type is present",
                });
            }
            if icmp_code.is_some() {
                return Err(DirFilterBuilderError::InvalidParameter {
                    parameter: "l4_proto",
                    reason: "icmp_code is present",
                });
            }
            if icmp_id.is_some() {
                return Err(DirFilterBuilderError::InvalidParameter {
                    parameter: "l4_proto",
                    reason: "icmp_id is present",
                });
            }
        }
        Ok(DirFilter {
            ipv4_src,
            ipv4_dst,
            l4_proto,
            l4_src_port,
            l4_dst_port,
            icmp_type,
            icmp_code,
            icmp_id,
            zone,
        })
    }

    pub fn ipv4_src(&mut self, value: impl Into<Ipv4Addr>) -> &mut Self {
        self.ipv4_src = Some(value.into());
        self
    }

    pub fn with_ipv4_src(mut self, value: impl Into<Ipv4Addr>) ->  Self {
        self.ipv4_src = Some(value.into());
        self
    }

    pub fn ipv4_dst(&mut self, value: impl Into<Ipv4Addr>) -> &mut Self {
        self.ipv4_dst = Some(value.into());
        self
    }

    pub fn with_ipv4_dst(mut self, value: impl Into<Ipv4Addr>) -> Self {
        self.ipv4_dst = Some(value.into());
        self
    }

    pub fn l4_proto(&mut self, value: impl Into<IpProto>) -> &mut Self {
        self.l4_proto = Some(value.into());
        self
    }

    pub fn with_l4_proto(mut self, value: impl Into<IpProto>) -> Self {
        self.l4_proto = Some(value.into());
        self
    }

    pub fn l4_src_port(&mut self, value: u16) -> &mut Self {
        self.l4_src_port = Some(value);
        self
    }

    pub fn with_l4_src_port(mut self, value: u16) -> Self {
        self.l4_src_port = Some(value);
        self
    }

    pub fn l4_dst_port(&mut self, value: u16) -> &mut Self {
        self.l4_dst_port = Some(value);
        self
    }

    pub fn with_l4_dst_port(mut self, value: u16) -> Self {
        self.l4_dst_port = Some(value);
        self
    }

    pub fn icmp_type(&mut self, value: u8) -> &mut Self {
        self.icmp_type = Some(value);
        self
    }

    pub fn with_icmp_type(mut self, value: u8) -> Self {
        self.icmp_type = Some(value);
        self
    }

    pub fn icmp_code(&mut self, value: u8) -> &mut Self {
        self.icmp_code = Some(value);
        self
    }

    pub fn with_icmp_code(mut self, value: u8) -> Self {
        self.icmp_code = Some(value);
        self
    }

    pub fn icmp_id(&mut self, value: u16) -> &mut Self {
        self.icmp_id = Some(value);
        self
    }

    pub fn with_icmp_id(mut self, value: u16) -> Self {
        self.icmp_id = Some(value);
        self
    }

    pub fn zone(&mut self, value: u16) -> &mut Self {
        self.zone = Some(value);
        self
    }

    pub fn with_zone(mut self, value: u16) -> Self {
        self.zone = Some(value);
        self
    }
}
