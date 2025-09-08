//! # Message
//! This module contains neli compatible subsystem messages.

use neli::neli_enum;

#[inline]
const fn subsys_message(subsys: CtNetlinkSubsys, msg: CtMessage) -> u16 {
    ((subsys as u16) << 8) | (msg as u16)
}

#[inline]
const fn subsys_event_message(subsys: CtNetlinkSubsys, msg: CtEventMessage) -> u16 {
    ((subsys as u16) << 8) | (msg as u16)
}

#[repr(u8)]
#[allow(unused)]
pub enum CtNetlinkSubsys {
    CtNetlink = libc::NFNL_SUBSYS_CTNETLINK as u8,
    CtNetlinkExp = libc::NFNL_SUBSYS_CTNETLINK_EXP as u8,
    CtNetlinkTimeout = libc::NFNL_SUBSYS_CTNETLINK_TIMEOUT as u8,
}

#[repr(u8)]
pub enum CtMessage {
    CtNew = 0u8,
    CtGet = 1u8,
    CtDelete = 2u8,
    CtGetCtrZero = 3u8,
    CtGetStatsCPU = 4u8,
    CtGetStats = 5u8,
    CtGetDying = 6u8,
    CtGetUnconfirmed = 7u8,
}

#[repr(u8)]
pub enum CtEventMessage {
    CtNew = 0u8,
    CtUpdate = 1u8,
    CtDestroy = 2u8,
}

#[neli_enum(serialized_type = "u16")]
pub enum CtNetlinkMessage {
    Conntrack = subsys_message(CtNetlinkSubsys::CtNetlink, CtMessage::CtGet),
    ConntrackNew = subsys_event_message(CtNetlinkSubsys::CtNetlink, CtEventMessage::CtNew),
    ConntrackUpdate = subsys_event_message(CtNetlinkSubsys::CtNetlink, CtEventMessage::CtUpdate),
    ConntrackDestroy = subsys_event_message(CtNetlinkSubsys::CtNetlink, CtEventMessage::CtDestroy),
}

impl neli::consts::nl::NlType for CtNetlinkMessage {}
