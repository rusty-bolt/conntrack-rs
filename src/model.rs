//! # Model
//! This module contains rust model structs for the decoded conntrack data.

use bitflags::bitflags;
use chrono::prelude::*;
use neli::neli_enum;
use serde::{Deserialize, Serialize};
use std::{net, time::Duration};

/// The `Flow` type contains all the information of a connection dumped from the
/// conntrack table. Note that the `Flow` type can be used to support multiple
/// extended formats as well to allow for expansions on the library. Thus, all
/// fields will be optional to support the various formats/options/configs
/// that can be set by the linux kernel.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Flow {
    /// Unique id assigned to this conntrack entry.
    pub id: Option<u32>,
    /// The origin of the network traffic, containing the `src` address and `sport`, the `dst`
    /// address and `dport`, and protocol information.
    pub origin: Option<IpTuple>,
    /// The reply of the network traffic, containing the `src` address and `sport`, the `dst`
    /// address and `dport`, and protocol information.
    pub reply: Option<IpTuple>,
    /// Metadata specific to the protocol being used to facilitate the network transfer.
    pub proto_info: Option<ProtoInfo>,
    /// Byte and packet counter data relative to the traffic origin. Enable with `sysctl
    /// -w net.netfilter.nf_conntrack_acct=1`
    pub counter_origin: Option<Counter>,
    /// Byte and packet counter data relative to the traffic reply. Enable with `sysctl
    /// -w net.netfilter.nf_conntrack_acct=1`
    pub counter_reply: Option<Counter>,
    /// Duration until conntrack entry is invalidated; reset to initial value when connection sees a new packet.
    /// Default TCP connection timeout is 5 days.
    pub timeout: Option<Duration>,
    /// Contains the status values parsed into the various status flags, represented as strings.
    pub status: Option<Vec<String>>,
    /// Use is a reference count for the connection used internally for garbage collection.
    pub entry_use: Option<u32>,
    pub zone: Option<u16>,
    pub mark: Option<u32>,
    pub mark_mask: Option<u32>,
    pub timestamp: Option<Timestamp>,
    pub status_mask: Option<u32>,
    pub helper: Option<Helper>,
    pub nat_src: Option<Nat>,
    pub seq_adj_orig: Option<SeqAdj>,
    pub seq_adj_repl: Option<SeqAdj>,
    pub sec_ctx: Option<SecCtx>,
    pub sec_mark: Option<u32>,
    pub exp: Option<Exp>,
}
#[neli_enum(serialized_type = "u8")]
#[derive(Serialize, Deserialize)]
pub enum IpProto {
    /// Dummy protocol for TCP  
    Ip = 0u8,
    /// Internet Control Message Protocol   
    Icmp = 1u8,
    /// Internet Group Management Protocol  
    Igmp = 2u8,
    /// IPIP tunnels (older KA9Q tunnels use 94)  
    Ipip = 4u8,
    /// Transmission Control Protocol   
    Tcp = 6u8,
    /// Exterior Gateway Protocol     
    Egp = 8u8,
    /// PUP protocol        
    Pup = 12u8,
    /// User Datagram Protocol    
    Udp = 17u8,
    /// XNS IDP protocol      
    Idp = 22u8,
    /// SO Transport Protocol Class 4   
    Tp = 29u8,
    /// Datagram Congestion Control Protocol  
    Dccp = 33u8,
    /// IPv6-in-IPv4 tunnelling     
    Ipv6 = 41u8,
    /// RSVP Protocol       
    Rsvp = 46u8,
    /// Cisco GRE tunnels (rfc 1701u8,
    Gre = 47u8,
    /// Encapsulation Security Payload protocol  
    Esp = 50u8,
    /// Authentication Header protocol  
    Ah = 51u8,
    /// Multicast Transport Protocol    
    Mtp = 92u8,
    /// IP option pseudo header for BEET  
    Beetph = 94u8,
    /// Encapsulation Header      
    Encap = 98u8,
    /// Protocol Independent Multicast  
    Pim = 103u8,
    /// Compression Header Protocol     
    Comp = 108u8,
    /// Layer 2 Tunnelling Protocol     
    L2tp = 115u8,
    /// Stream Control Transport Protocol   
    Sctp = 132u8,
    /// UDP-Lite (RFC 3828)       
    Udplite = 136u8,
    /// MPLS in IP (RFC 4023)     
    Mpls = 137u8,
    /// Ethernet-within-IPv6 Encapsulation  
    Ethernet = 143u8,
    /// Raw IP packets      
    Raw = 255u8,
}

/// IPTuple contains the source and destination IP as well as protocol information
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct IpTuple {
    pub src: Option<net::IpAddr>,
    pub dst: Option<net::IpAddr>,
    pub proto: Option<ProtoTuple>,
    pub zone: Option<u16>,
}

/// ProtoTuple contains information about the used protocol
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct ProtoTuple {
    pub number: Option<IpProto>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub icmp_id: Option<u16>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub icmpv6_id: Option<u16>,
    pub icmpv6_type: Option<u8>,
    pub icmpv6_code: Option<u8>,
}

/// ProtoInfo contains additional information for certain protocols
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct ProtoInfo {
    pub tcp: Option<TcpInfo>,
    pub dccp: Option<DccpInfo>,
    pub sctp: Option<SctpInfo>,
}

#[neli_enum(serialized_type = "u8")]
#[derive(Serialize, Deserialize)]
pub enum TcpState {
    None = 0u8,
    SynSent = 1u8,
    SynRecv = 2u8,
    Established = 3u8,
    FinWait = 4u8,
    CloseWait = 5u8,
    LastAck = 6u8,
    TimeWait = 7u8,
    Close = 8u8,
    SynSent2 = 9u8,
}

// TCPInfo contains additional information for TCP sessions
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct TcpInfo {
    pub state: Option<TcpState>,
    pub wscale_orig: Option<u8>,
    pub wscale_repl: Option<u8>,
    pub flags_orig: Option<TcpFlags>,
    pub flags_reply: Option<TcpFlags>,
}

// TCPFlags contains additional information for TCP flags
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct TcpFlags {
    pub flags: Option<u8>,
    pub mask: Option<u8>,
}

#[neli_enum(serialized_type = "u8")]
#[derive(Serialize, Deserialize)]
pub enum DccpState {
    None = 0u8,
    Request = 1u8,
    Response = 2u8,
    PartOpen = 3u8,
    Open = 4u8,
    CloseReq = 5u8,
    Closing = 6u8,
    Timewait = 7u8,
    Ignore = 8u8,
    Invalid = 9u8,
}

// DccpInfo contains additional information for DCCP sessions
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct DccpInfo {
    pub state: Option<DccpState>,
    pub role: Option<u8>,
    pub handshake_seq: Option<u64>,
}

#[neli_enum(serialized_type = "u8")]
#[derive(Serialize, Deserialize)]
pub enum SctpState {
    None = 0u8,
    Closed = 1u8,
    CookieWait = 2u8,
    CookieEchoed = 3u8,
    Established = 4u8,
    ShutdownSent = 5u8,
    ShutdownRecd = 6u8,
    ShutdownAckSent = 7u8,
    HeartbeatSent = 8u8,
}

// contains additional information for SCTP sessions
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SctpInfo {
    pub state: Option<SctpState>,
    pub vtag_original: Option<u32>,
    pub vtag_reply: Option<u32>,
}

#[derive(Copy, Clone, Default, Debug, Serialize, Deserialize)]
pub struct SrcDst(pub Option<net::IpAddr>, pub Option<net::IpAddr>);

// Helper contains additional information
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Helper {
    pub name: Option<String>,
    pub info: Option<String>,
}

// SeqAdj contains additional information about corrections
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SeqAdj {
    pub correction_pos: Option<u32>,
    pub offset_before: Option<u32>,
    pub offset_after: Option<u32>,
}

// Counter contains additional information about the traffic
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Counter {
    pub packets: Option<u64>,
    pub bytes: Option<u64>,
}

// SecCtx contains additional information about the security context
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SecCtx {
    pub name: Option<String>,
}

// Timestamp contains start and/or stop times
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Timestamp {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
}

// NatInfo contains addition NAT information of a connection
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct NatInfo {
    pub dir: Option<u32>,
    pub tuple: Option<IpTuple>,
}

// Exp extends the information of a connection by information from the expected table
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Exp {
    pub naster: Option<IpTuple>,
    pub tuple: Option<IpTuple>,
    pub nask: Option<IpTuple>,
    pub flags: Option<u32>,
    pub class: Option<u32>,
    pub id: Option<u32>,
    pub timeout: Option<u32>,
    pub zone: Option<u16>,
    pub helper_name: Option<String>,
    pub fnn: Option<String>,
    pub nat: Option<NatInfo>,
}

// Nat contains information for source/destination NAT
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Nat {
    pub ip_min: Option<net::IpAddr>,
    pub ip_max: Option<net::IpAddr>,
    pub proto: Option<ProtoTuple>,
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct StatusFlags: u32 {
        const StatusExpected = 1;
        const StatusSeenReply = 1 << 1;
        const StatusAssured = 1 << 2;
        const StatusConfirmed = 1 << 3;
        const StatusSrcNAT = 1 << 4;
        const StatusDstNAT = 1 << 5;
        const StatusNATMask = Self::StatusDstNAT.bits() | Self::StatusSrcNAT.bits();
        const StatusSeqAdjust = 1 << 6;
        const StatusSrcNATDone = 1 << 7;
        const StatusDstNATDone = 1 << 8;
        const StatusNATDoneMask = Self::StatusDstNATDone.bits() | Self::StatusSrcNATDone.bits();
        const StatusDying = 1 << 9;
        const StatusFixedTimeout = 1 << 10;
        const StatusTemplate = 1 << 11;
        const StatusUntracked = 1 << 12;
        const StatusHelper = 1 << 13;
        const StatusOffload = 1 << 14;
    }
}
