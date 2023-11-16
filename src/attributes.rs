//! # Attributes
//! This module contains neli compatible attributes used to read and decode
//! conntrack subsystem responses.

use neli::{
    attr::AttrHandle,
    consts::genl::NlAttrType,
    genl::Nlattr,
    neli_enum,
    types::{Buffer, GenlBuffer},
};

/// CtAttrHabndle is a type alias for a neli `AttrHandle` for `GenlBuffer` and
/// `Nlattr`. It's a convenience for attribute decoding methods.
pub type CtAttrHandle<'a, T> = AttrHandle<'a, GenlBuffer<T, Buffer>, Nlattr<T, Buffer>>;

#[neli_enum(serialized_type = "u16")]
pub enum ConntrackAttr {
    CtaUnspec = 0u16,
    CtaTupleOrig = 1u16,
    CtaTupleReply = 2u16,
    CtaStatus = 3u16,
    CtaProtoInfo = 4u16,
    CtaHelp = 5u16,
    CtaNatSrc = 6u16,
    CtaTimeout = 7u16,
    CtaMark = 8u16,
    CtaCountersOrig = 9u16,
    CtaCountersReply = 10u16,
    CtaUse = 11u16,
    CtaId = 12u16,
    CtaNatDst = 13u16,
    CtaTupleMaster = 14u16,
    CtaSeqAdjOrig = 15u16,
    CtaSeqAdjReply = 16u16,
    CtaSecMark = 17u16,
    CtaZone = 18u16,
    CtaSecCtx = 19u16,
    CtaTimestamp = 20u16,
    CtaMarkMask = 21u16,
    CtaLabels = 22u16,
    CtaLabelsMask = 23u16,
    CtaSynProxy = 24u16,
    CtaFilter = 25u16,
    CtaStatusMask = 26u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum TupleAttr {
    CtaUnspec = 0u16,
    CtaTupleIp = 1u16,
    CtaTupleProto = 2u16,
    CtaTupleZone = 3u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum IpTupleAttr {
    CtaIpUnspec = 0u16,
    CtaIpv4Src = 1u16,
    CtaIpv4Dst = 2u16,
    CtaIpv6Src = 3u16,
    CtaIpv6Dst = 4u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum ProtoTupleAttr {
    CtaProtoUnspec = 0u16,
    CtaProtoNum = 1u16,
    CtaProtoSrcPort = 2u16,
    CtaProtoDstPort = 3u16,
    CtaProtoIcmpId = 4u16,
    CtaProtoIcmpType = 5u16,
    CtaProtoIcmpCode = 6u16,
    CtaProtoIcmpV6Id = 7u16,
    CtaProtoIcmpV6Type = 8u16,
    CtaProtoIcmpV6Code = 9u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum ExpectNatAttr {
    CtaExpectNatUnspec = 0u16,
    CtaExpectNatDir = 1u16,
    CtaExpectNatTuple = 2u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum TimestampAttr {
    CtaTimestampUnspec = 0u16,
    CtaTimestampStart = 1u16,
    CtaTimestampStop = 2u16,
    CtaTimestampPad = 3u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum CounterAttr {
    CtaCountersUnspec = 0u16,
    CtaCountersPackets = 1u16,
    CtaCountersBytes = 2u16,
    CtaCountersPackets32 = 3u16,
    CtaCountersBytes32 = 4u16,
    CtaCountersPad = 5u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum ProtoInfoAttr {
    CtaProtoInfoUnspec = 0u16,
    CtaProtoInfoTcp = 1u16,
    CtaProtoInfoDccp = 2u16,
    CtaProtoInfoSctp = 3u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum TcpInfoAttr {
    CtaProtoInfoTcpUnspec = 0u16,
    CtaProtoInfoTcpState = 1u16,
    CtaProtoInfoTcpWScaleOriginal = 2u16,
    CtaProtoInfoTcpWScaleReply = 3u16,
    CtaProtoInfoTcpFlagsOriginal = 4u16,
    CtaProtoInfoTcpFlagsReply = 5u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum DccpInfoAttr {
    CtaProtoInfoDccpUnspec = 0u16,
    CtaProtoInfoDccpState = 1u16,
    CtaProtoInfoDccpRole = 2u16,
    CtaProtoInfoDccpHandshakeSeq = 3u16,
    CtaProtoInfoDccpPad = 4u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum SctpInfoAttr {
    CtaProtoInfoSctpUnspec = 0u16,
    CtaProtoInfoSctpState = 1u16,
    CtaProtoInfoSctpVTagOriginal = 2u16,
    CtaProtoInfoSctpVtagReply = 3u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum ExpectAttr {
    CtaExpectUnspec = 0u16,
    CtaExpectMaster = 1u16,
    CtaExpectTuple = 2u16,
    CtaExpectMask = 3u16,
    CtaExpectTimeout = 4u16,
    CtaExpectID = 5u16,
    CtaExpectHelpName = 6u16,
    CtaExpectZone = 7u16,
    CtaExpectFlags = 8u16,
    CtaExpectClass = 9u16,
    CtaExpectNat = 10u16,
    CtaExpectFN = 11u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum HelperAttr {
    CtaHelpUnspec = 0u16,
    CtaHelpName = 1u16,
    CtaHelpInfo = 2u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum SynProxyAttr {
    CtaSynProxyUnspec = 0u16,
    CtaSynProxyISN = 1u16,
    CtaSynProxyITS = 2u16,
    CtaSynProxyTSOff = 3u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum CpuStatsAttr {
    CtaStatsUnspec = 0u16,
    CtaStatsSearched = 1u16,
    CtaStatsFound = 2u16,
    CtaStatsNew = 3u16,
    CtaStatsInvalid = 4u16,
    CtaStatsIgnore = 5u16,
    CtaStatsDelete = 6u16,
    CtaStatsDeleteList = 7u16,
    CtaStatsInsert = 8u16,
    CtaStatsInsertFailed = 9u16,
    CtaStatsDrop = 10u16,
    CtaStatsEarlyDrop = 11u16,
    CtaStatsError = 12u16,
    CtaStatsSearchRestart = 13u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum SecCtxAttr {
    CtaSecCtxUnspec = 0u16,
    CtaSecCtxName = 1u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum SeqAdjAttr {
    CtaSeqAdjUnspec = 0u16,
    CtaSeqAdjCorrectionPos = 1u16,
    CtaSeqAdjOffsetBefore = 2u16,
    CtaSeqAdjOffsetAfter = 3u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum NatAttr {
    CtaNatUnspec = 0u16,
    CtaNatv4MinIp = 1u16,
    CtaNatv4MaxIp = 2u16,
    CtaNatProto = 3u16,
    CtaNatv6MinIp = 4u16,
    CtaNatv6MaxIp = 6u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum GlobalStatsAttr {
    CtaStatsGlobalUnspec = 0u16,
    CtaStatsGlobalEntries = 1u16,
    CtaStatsGlobalMaxEntries = 2u16,
}

#[neli_enum(serialized_type = "u16")]
pub enum ExpectStatsAttr {
    CtaStatsExpUnspec = 0u16,
    CtaStatsExpNew = 1u16,
    CtaStatsExpCreate = 2u16,
    CtaStatsExpDelete = 3u16,
}

impl NlAttrType for ConntrackAttr {}
impl NlAttrType for TupleAttr {}
impl NlAttrType for IpTupleAttr {}
impl NlAttrType for ProtoTupleAttr {}
impl NlAttrType for TimestampAttr {}
impl NlAttrType for CounterAttr {}
impl NlAttrType for ProtoInfoAttr {}
impl NlAttrType for TcpInfoAttr {}
impl NlAttrType for DccpInfoAttr {}
impl NlAttrType for SctpInfoAttr {}
impl NlAttrType for ExpectAttr {}
impl NlAttrType for HelperAttr {}
impl NlAttrType for SecCtxAttr {}
impl NlAttrType for ExpectStatsAttr {}
impl NlAttrType for SeqAdjAttr {}
impl NlAttrType for GlobalStatsAttr {}
impl NlAttrType for SynProxyAttr {}
impl NlAttrType for CpuStatsAttr {}
impl NlAttrType for ExpectNatAttr {}
impl NlAttrType for NatAttr {}
