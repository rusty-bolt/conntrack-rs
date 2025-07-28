//! # Decoders
//! This module contains decoder traits and implementations capable of extracting
//! conntrack table data from neli attributes.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;

use chrono::TimeZone;
use chrono::Utc;
use neli::types::Buffer;
use neli::{attr::Attribute, consts::genl::*, genl::Nlattr};

use crate::attributes::*;
use crate::model::*;
use crate::result::*;

/// The attribute decoder trait is implemented to convert a specific `AttrHandle` to a
/// conntrack model. This will be the primary mechanism used to decode nested conntrack
/// attributes.
pub trait AttrDecoder<'a, T, M>
where
    T: NlAttrType,
{
    fn decode(attr_handle: CtAttrHandle<'a, T>) -> Result<M>;
}

/// A primitive attribute decoder is used to extract numerical values from
/// attributes.
pub trait PrimitiveAttrDecoder<T, M>
where
    T: NlAttrType,
{
    fn decode(attr: &Nlattr<T, Buffer>) -> Result<M>;
}

/// A decoder capable of decoding `IpAddr` instances from an Attribute.
pub trait IpDecoder<T>
where
    T: NlAttrType,
{
    fn decode_v4(attr: &Nlattr<T, Buffer>) -> Result<IpAddr>;
    fn decode_v6(attr: &Nlattr<T, Buffer>) -> Result<IpAddr>;
}

impl<T: NlAttrType> IpDecoder<T> for IpAddr {
    fn decode_v4(attr: &Nlattr<T, Buffer>) -> Result<IpAddr> {
        let ip: Ipv4Addr = Ipv4Addr::from(u32::decode(attr)?);
        Ok(IpAddr::V4(ip))
    }
    fn decode_v6(attr: &Nlattr<T, Buffer>) -> Result<IpAddr> {
        let ip: Ipv6Addr = Ipv6Addr::from(u128::decode(attr)?);
        Ok(IpAddr::V6(ip))
    }
}

impl<T: NlAttrType> PrimitiveAttrDecoder<T, u128> for u128 {
    fn decode(attr: &Nlattr<T, Buffer>) -> Result<u128> {
        Ok(u128::from_be(attr.get_payload_as::<u128>()?))
    }
}

impl<T: NlAttrType> PrimitiveAttrDecoder<T, u64> for u64 {
    fn decode(attr: &Nlattr<T, Buffer>) -> Result<u64> {
        Ok(u64::from_be(attr.get_payload_as::<u64>()?))
    }
}

impl<T: NlAttrType> PrimitiveAttrDecoder<T, u32> for u32 {
    fn decode(attr: &Nlattr<T, Buffer>) -> Result<u32> {
        Ok(u32::from_be(attr.get_payload_as::<u32>()?))
    }
}

impl<T: NlAttrType> PrimitiveAttrDecoder<T, u16> for u16 {
    fn decode(attr: &Nlattr<T, Buffer>) -> Result<u16> {
        Ok(u16::from_be(attr.get_payload_as::<u16>()?))
    }
}

impl<T: NlAttrType> PrimitiveAttrDecoder<T, u8> for u8 {
    fn decode(attr: &Nlattr<T, Buffer>) -> Result<u8> {
        Ok(u8::from_be(attr.get_payload_as::<u8>()?))
    }
}

impl<T: NlAttrType> PrimitiveAttrDecoder<T, Vec<String>> for StatusFlags {
    fn decode(attr: &Nlattr<T, Buffer>) -> Result<Vec<String>> {
        let status = u32::from_be(attr.get_payload_as::<u32>()?);
        let status_flags = StatusFlags::from_bits_retain(status);

        let mut v = vec![];
        for (flag, _) in status_flags.iter_names() {
            v.push(flag.to_string());
        }

        Ok(v)
    }
}

impl<'a> AttrDecoder<'a, ConntrackAttr, Flow> for Flow {
    fn decode(attr_handle: CtAttrHandle<'a, ConntrackAttr>) -> Result<Flow> {
        let mut flow = Flow::default();

        for attr in attr_handle.iter() {
            match &attr.nla_type().nla_type() {
                ConntrackAttr::CtaId => {
                    flow.id = Some(u32::decode(attr)?);
                }
                ConntrackAttr::CtaProtoInfo => {
                    let info_attr = attr.get_attr_handle::<ProtoInfoAttr>()?;

                    flow.proto_info = Some(ProtoInfo::decode(info_attr)?);
                }
                ConntrackAttr::CtaTupleOrig => {
                    let tuple_attr = attr.get_attr_handle::<TupleAttr>()?;

                    flow.origin = Some(IpTuple::decode(tuple_attr)?);
                }
                ConntrackAttr::CtaCountersOrig => {
                    let counter = attr.get_attr_handle::<CounterAttr>()?;

                    flow.counter_origin = Some(Counter::decode(counter)?);
                }
                ConntrackAttr::CtaTupleReply => {
                    let tuple_attr = attr.get_attr_handle::<TupleAttr>()?;

                    flow.reply = Some(IpTuple::decode(tuple_attr)?);
                }
                ConntrackAttr::CtaCountersReply => {
                    let counter = attr.get_attr_handle::<CounterAttr>()?;

                    flow.counter_reply = Some(Counter::decode(counter)?);
                }
                ConntrackAttr::CtaTimestamp => {
                    let timestamp_attr = attr.get_attr_handle::<TimestampAttr>()?;

                    flow.timestamp = Some(Timestamp::decode(timestamp_attr)?);
                }
                ConntrackAttr::CtaStatus => {
                    flow.status = Some(StatusFlags::decode(attr)?);
                }
                ConntrackAttr::CtaStatusMask => {
                    flow.status_mask = Some(u32::decode(attr)?);
                }
                ConntrackAttr::CtaTimeout => {
                    flow.timeout = Some(Duration::from_secs((u32::decode(attr)?) as u64));
                }
                ConntrackAttr::CtaMark => {
                    flow.mark = Some(u32::decode(attr)?);
                }
                ConntrackAttr::CtaSeqAdjOrig => {
                    let seq_adj_orig_attr = attr.get_attr_handle::<SeqAdjAttr>()?;

                    flow.seq_adj_orig = Some(SeqAdj::decode(seq_adj_orig_attr)?);
                }
                ConntrackAttr::CtaSeqAdjReply => {
                    let seq_adj_reply_attr = attr.get_attr_handle::<SeqAdjAttr>()?;

                    flow.seq_adj_repl = Some(SeqAdj::decode(seq_adj_reply_attr)?);
                }
                ConntrackAttr::CtaZone => {
                    flow.zone = Some(u16::decode(attr)?);
                }
                ConntrackAttr::CtaSecCtx => {
                    let sec_ctx_attr = attr.get_attr_handle::<SecCtxAttr>()?;

                    flow.sec_ctx = Some(SecCtx::decode(sec_ctx_attr)?);
                }
                ConntrackAttr::CtaSecMark => {
                    flow.sec_mark = Some(u32::decode(attr)?);
                }
                ConntrackAttr::CtaMarkMask => {
                    flow.mark_mask = Some(u32::decode(attr)?);
                }
                ConntrackAttr::CtaUse => {
                    flow.entry_use = Some(u32::decode(attr)?);
                }
                ConntrackAttr::CtaNatSrc => {
                    let nat_src_attr = attr.get_attr_handle::<NatAttr>()?;

                    flow.nat_src = Some(Nat::decode(nat_src_attr)?);
                }
                ConntrackAttr::CtaHelp => {
                    let helper_attr = attr.get_attr_handle::<HelperAttr>()?;

                    flow.helper = Some(Helper::decode(helper_attr)?);
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }

        Ok(flow)
    }
}

impl<'a> AttrDecoder<'a, NatAttr, Nat> for Nat {
    fn decode(attr_handle: CtAttrHandle<'a, NatAttr>) -> Result<Nat> {
        let mut nat = Nat::default();

        for inner_attr in attr_handle.iter() {
            match &inner_attr.nla_type().nla_type() {
                NatAttr::CtaNatProto => {
                    let proto_tuple_attr = inner_attr.get_attr_handle::<ProtoTupleAttr>()?;
                    nat.proto = Some(ProtoTuple::decode(proto_tuple_attr)?);
                }
                NatAttr::CtaNatv4MinIp => {
                    nat.ip_min = Some(IpAddr::decode_v4(inner_attr)?);
                }
                NatAttr::CtaNatv4MaxIp => {
                    nat.ip_max = Some(IpAddr::decode_v4(inner_attr)?);
                }
                NatAttr::CtaNatv6MinIp => {
                    nat.ip_min = Some(IpAddr::decode_v6(inner_attr)?);
                }
                NatAttr::CtaNatv6MaxIp => {
                    nat.ip_max = Some(IpAddr::decode_v6(inner_attr)?);
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }

        Ok(nat)
    }
}

impl<'a> AttrDecoder<'a, HelperAttr, Helper> for Helper {
    fn decode(attr_handle: CtAttrHandle<'a, HelperAttr>) -> Result<Helper> {
        let mut helper = Helper::default();

        for inner_attr in attr_handle.iter() {
            match &inner_attr.nla_type().nla_type() {
                HelperAttr::CtaHelpName => {
                    let name =
                        String::from_utf8_lossy(inner_attr.nla_payload().as_ref()).to_string();
                    helper.name = Some(name);
                }
                HelperAttr::CtaHelpInfo => {
                    let info =
                        String::from_utf8_lossy(inner_attr.nla_payload().as_ref()).to_string();
                    helper.info = Some(info);
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }

        Ok(helper)
    }
}

impl<'a> AttrDecoder<'a, SecCtxAttr, SecCtx> for SecCtx {
    fn decode(attr_handle: CtAttrHandle<'a, SecCtxAttr>) -> Result<SecCtx> {
        let mut sec_ctx = SecCtx::default();

        for inner_attr in attr_handle.iter() {
            match &inner_attr.nla_type().nla_type() {
                SecCtxAttr::CtaSecCtxName => {
                    let name =
                        String::from_utf8_lossy(inner_attr.nla_payload().as_ref()).to_string();
                    sec_ctx.name = Some(name);
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }

        Ok(sec_ctx)
    }
}

impl<'a> AttrDecoder<'a, SeqAdjAttr, SeqAdj> for SeqAdj {
    fn decode(attr_handle: CtAttrHandle<'a, SeqAdjAttr>) -> Result<SeqAdj> {
        let mut seq_adj = SeqAdj::default();

        for inner_attr in attr_handle.iter() {
            match &inner_attr.nla_type().nla_type() {
                SeqAdjAttr::CtaSeqAdjCorrectionPos => {
                    seq_adj.correction_pos = Some(u32::decode(inner_attr)?);
                }
                SeqAdjAttr::CtaSeqAdjOffsetAfter => {
                    seq_adj.offset_after = Some(u32::decode(inner_attr)?);
                }
                SeqAdjAttr::CtaSeqAdjOffsetBefore => {
                    seq_adj.offset_before = Some(u32::decode(inner_attr)?);
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }
        Ok(seq_adj)
    }
}

impl<'a> AttrDecoder<'a, ProtoInfoAttr, ProtoInfo> for ProtoInfo {
    fn decode(attr_handle: CtAttrHandle<'a, ProtoInfoAttr>) -> Result<ProtoInfo> {
        let mut proto_info = ProtoInfo::default();

        for inner_attr in attr_handle.iter() {
            match &inner_attr.nla_type().nla_type() {
                ProtoInfoAttr::CtaProtoInfoTcp => {
                    let tcp_info_attr = inner_attr.get_attr_handle::<TcpInfoAttr>()?;
                    proto_info.tcp = Some(TcpInfo::decode(tcp_info_attr)?);
                }
                ProtoInfoAttr::CtaProtoInfoDccp => {
                    let dccp_info_attr = inner_attr.get_attr_handle::<DccpInfoAttr>()?;
                    proto_info.dccp = Some(DccpInfo::decode(dccp_info_attr)?);
                }
                ProtoInfoAttr::CtaProtoInfoSctp => {
                    let sctp_info_attr = inner_attr.get_attr_handle::<SctpInfoAttr>()?;
                    proto_info.sctp = Some(SctpInfo::decode(sctp_info_attr)?);
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }

        Ok(proto_info)
    }
}

impl<'a> AttrDecoder<'a, TcpInfoAttr, TcpInfo> for TcpInfo {
    fn decode(attr_handle: CtAttrHandle<'a, TcpInfoAttr>) -> Result<TcpInfo> {
        let mut tcp_info = TcpInfo::default();

        for inner_attr in attr_handle.iter() {
            match &inner_attr.nla_type().nla_type() {
                TcpInfoAttr::CtaProtoInfoTcpState => {
                    tcp_info.state = Some(TcpState::from(u8::decode(inner_attr)?));
                }
                TcpInfoAttr::CtaProtoInfoTcpFlagsOriginal => {
                    let bytes = Vec::<u8>::from(inner_attr.nla_payload().as_ref());
                    if bytes.len() != 2 {
                        let flags = TcpFlags {
                            flags: Some(bytes[0]),
                            mask: Some(bytes[1]),
                        };
                        tcp_info.flags_orig = Some(flags);
                    }
                }
                TcpInfoAttr::CtaProtoInfoTcpFlagsReply => {
                    let bytes = Vec::<u8>::from(inner_attr.nla_payload().as_ref());
                    if bytes.len() != 2 {
                        let flags = TcpFlags {
                            flags: Some(bytes[0]),
                            mask: Some(bytes[1]),
                        };
                        tcp_info.flags_reply = Some(flags);
                    }
                }
                TcpInfoAttr::CtaProtoInfoTcpWScaleOriginal => {
                    tcp_info.wscale_orig = Some(u8::decode(inner_attr)?);
                }
                TcpInfoAttr::CtaProtoInfoTcpWScaleReply => {
                    tcp_info.wscale_repl = Some(u8::decode(inner_attr)?);
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }

        Ok(tcp_info)
    }
}

impl<'a> AttrDecoder<'a, DccpInfoAttr, DccpInfo> for DccpInfo {
    fn decode(attr_handle: CtAttrHandle<'a, DccpInfoAttr>) -> Result<DccpInfo> {
        let mut dccp_info = DccpInfo::default();

        for inner_attr in attr_handle.iter() {
            match &inner_attr.nla_type().nla_type() {
                DccpInfoAttr::CtaProtoInfoDccpState => {
                    let state = u8::decode(inner_attr)?;
                    dccp_info.state = Some(DccpState::from(state));
                }
                DccpInfoAttr::CtaProtoInfoDccpRole => {
                    dccp_info.role = Some(u8::decode(inner_attr)?);
                }
                DccpInfoAttr::CtaProtoInfoDccpHandshakeSeq => {
                    dccp_info.handshake_seq = Some(u64::decode(inner_attr)?);
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }

        Ok(dccp_info)
    }
}

impl<'a> AttrDecoder<'a, SctpInfoAttr, SctpInfo> for SctpInfo {
    fn decode(attr_handle: CtAttrHandle<'a, SctpInfoAttr>) -> Result<SctpInfo> {
        let mut sctp_info = SctpInfo::default();

        for inner_attr in attr_handle.iter() {
            match &inner_attr.nla_type().nla_type() {
                SctpInfoAttr::CtaProtoInfoSctpState => {
                    let state = u8::decode(inner_attr)?;
                    sctp_info.state = Some(SctpState::from(state));
                }
                SctpInfoAttr::CtaProtoInfoSctpVTagOriginal => {
                    sctp_info.vtag_original = Some(u32::decode(inner_attr)?);
                }
                SctpInfoAttr::CtaProtoInfoSctpVtagReply => {
                    sctp_info.vtag_reply = Some(u32::decode(inner_attr)?);
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }

        Ok(sctp_info)
    }
}

impl<'a> AttrDecoder<'a, TimestampAttr, Timestamp> for Timestamp {
    fn decode(attr_handle: CtAttrHandle<'a, TimestampAttr>) -> Result<Timestamp> {
        let mut timestamp = Timestamp::default();

        for inner_attr in attr_handle.iter() {
            match &inner_attr.nla_type().nla_type() {
                TimestampAttr::CtaTimestampStart => {
                    let ts_start = u64::from_be(inner_attr.get_payload_as::<u64>()?);
                    timestamp.start = Some(Utc.timestamp_nanos(ts_start as i64));
                }
                TimestampAttr::CtaTimestampStop => {
                    let ts_end = u64::from_be(inner_attr.get_payload_as::<u64>()?);
                    timestamp.end = Some(Utc.timestamp_nanos(ts_end as i64));
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }

        Ok(timestamp)
    }
}

impl<'a> AttrDecoder<'a, CounterAttr, Counter> for Counter {
    fn decode(attr_handle: CtAttrHandle<'a, CounterAttr>) -> Result<Counter> {
        let mut counter = Counter::default();

        for inner_attr in attr_handle.iter() {
            match &inner_attr.nla_type().nla_type() {
                CounterAttr::CtaCountersPackets => {
                    counter.packets = Some(u64::decode(inner_attr)?);
                }
                CounterAttr::CtaCountersBytes => {
                    counter.bytes = Some(u64::decode(inner_attr)?);
                }
                CounterAttr::CtaCountersPackets32 => {
                    let packets = u32::decode(inner_attr)?;
                    counter.packets = Some(packets as u64);
                }
                CounterAttr::CtaCountersBytes32 => {
                    let bytes = u32::decode(inner_attr)?;
                    counter.bytes = Some(bytes as u64);
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }

        Ok(counter)
    }
}

impl<'a> AttrDecoder<'a, TupleAttr, IpTuple> for IpTuple {
    fn decode(attr_handle: CtAttrHandle<'a, TupleAttr>) -> Result<IpTuple> {
        let mut ip_tuple = IpTuple::default();

        for inner_attr in attr_handle.iter() {
            match &inner_attr.nla_type().nla_type() {
                TupleAttr::CtaTupleIp => {
                    let ip_tuple_attr = inner_attr.get_attr_handle::<IpTupleAttr>()?;
                    SrcDst(ip_tuple.src, ip_tuple.dst) = SrcDst::decode(ip_tuple_attr)?;
                }
                TupleAttr::CtaTupleProto => {
                    let proto_attr = inner_attr.get_attr_handle::<ProtoTupleAttr>()?;
                    ip_tuple.proto = Some(ProtoTuple::decode(proto_attr)?);
                }
                TupleAttr::CtaTupleZone => {
                    ip_tuple.zone = Some(u16::decode(inner_attr)?);
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }

        Ok(ip_tuple)
    }
}

impl<'a> AttrDecoder<'a, IpTupleAttr, SrcDst> for SrcDst {
    fn decode(attr_handle: CtAttrHandle<'a, IpTupleAttr>) -> Result<SrcDst> {
        let mut src_dst = SrcDst::default();

        for ip_inner in attr_handle.iter() {
            match &ip_inner.nla_type().nla_type() {
                IpTupleAttr::CtaIpv4Src => {
                    src_dst.0 = Some(IpAddr::decode_v4(ip_inner)?);
                }
                IpTupleAttr::CtaIpv4Dst => {
                    src_dst.1 = Some(IpAddr::decode_v4(ip_inner)?);
                }
                IpTupleAttr::CtaIpv6Src => {
                    src_dst.0 = Some(IpAddr::decode_v6(ip_inner)?);
                }
                IpTupleAttr::CtaIpv6Dst => {
                    src_dst.1 = Some(IpAddr::decode_v6(ip_inner)?);
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }

        Ok(src_dst)
    }
}

impl<'a> AttrDecoder<'a, ProtoTupleAttr, ProtoTuple> for ProtoTuple {
    fn decode(attr_handle: CtAttrHandle<'a, ProtoTupleAttr>) -> Result<ProtoTuple> {
        let mut tuple = ProtoTuple::default();

        for attr in attr_handle.iter() {
            match &attr.nla_type().nla_type() {
                ProtoTupleAttr::CtaProtoNum => {
                    tuple.number = Some(IpProto::from(u8::decode(attr)?));
                }
                ProtoTupleAttr::CtaProtoSrcPort => {
                    tuple.src_port = Some(u16::decode(attr)?);
                }
                ProtoTupleAttr::CtaProtoDstPort => {
                    tuple.dst_port = Some(u16::decode(attr)?);
                }
                ProtoTupleAttr::CtaProtoIcmpId => {
                    tuple.icmp_id = Some(u16::decode(attr)?);
                }
                ProtoTupleAttr::CtaProtoIcmpType => {
                    tuple.icmp_type = Some(u8::decode(attr)?);
                }
                ProtoTupleAttr::CtaProtoIcmpCode => {
                    tuple.icmp_code = Some(u8::decode(attr)?);
                }
                ProtoTupleAttr::CtaProtoIcmpV6Id => {
                    tuple.icmpv6_id = Some(u16::decode(attr)?);
                }
                ProtoTupleAttr::CtaProtoIcmpV6Type => {
                    tuple.icmpv6_type = Some(u8::decode(attr)?);
                }
                ProtoTupleAttr::CtaProtoIcmpV6Code => {
                    tuple.icmpv6_code = Some(u8::decode(attr)?);
                }
                other => {
                    log::warn!("Failed to handle attribute: {other:?}");
                }
            }
        }

        Ok(tuple)
    }
}
