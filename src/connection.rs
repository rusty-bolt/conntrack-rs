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
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

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

    /// Start monitoring conntrack events in real-time.
    /// This method creates a background thread that continuously listens for events
    /// and sends them through a channel.
    /// 
    /// # Arguments
    /// * `event_mask` - Which events to monitor (NEW, UPDATE, DESTROY)
    /// * `buffer_size` - Optional netlink socket buffer size in bytes
    /// * `debug` - Enable debug output
    /// 
    /// # Returns
    /// A receiver that will receive `ConntrackEvent` instances as they occur.
    /// 
    /// # Example
    /// ```rust
    /// use conntrack::*;
    /// 
    /// let mut ct = Conntrack::connect()?;
    /// let event_mask = EventMask::all();
    /// let receiver = ct.monitor_events(event_mask, None, false)?;
    /// 
    /// // Process events as they come in
    /// for event in receiver {
    ///     println!("Event: {:?}", event);
    /// }
    /// ```
    pub fn monitor_events(
        &mut self,
        event_mask: EventMask,
        buffer_size: Option<usize>,
        debug: bool,
    ) -> Result<mpsc::Receiver<ConntrackEvent>> {
        let (tx, rx) = mpsc::channel();
        
        if debug {
            log::info!("Setting up event monitoring with mask: {:?}", event_mask);
            log::info!("Netlink flags: 0x{:x}", event_mask.to_netlink_flags());
        }
        
        // Create a new socket for event monitoring
        // The key issue was here - we need to join the multicast groups, not pass flags to connect
        let mut event_socket = NlSocketHandle::connect(NlFamily::Netfilter, None, Groups::empty())?;
        
        // Join the multicast groups for the events we want to monitor
        // Using the correct neli API - we need to create Groups objects
        if event_mask.new {
            let groups = Groups::new_groups(&[libc::NFNLGRP_CONNTRACK_NEW as u32]);
            event_socket.add_mcast_membership(groups)?;
            if debug {
                log::info!("Joined NEW events group: {}", libc::NFNLGRP_CONNTRACK_NEW);
            }
        }
        if event_mask.update {
            let groups = Groups::new_groups(&[libc::NFNLGRP_CONNTRACK_UPDATE as u32]);
            event_socket.add_mcast_membership(groups)?;
            if debug {
                log::info!("Joined UPDATE events group: {}", libc::NFNLGRP_CONNTRACK_UPDATE);
            }
        }
        if event_mask.destroy {
            let groups = Groups::new_groups(&[libc::NFNLGRP_CONNTRACK_DESTROY as u32]);
            event_socket.add_mcast_membership(groups)?;
            if debug {
                log::info!("Joined DESTROY events group: {}", libc::NFNLGRP_CONNTRACK_DESTROY);
            }
        }
        
        if debug {
            log::info!("Successfully joined multicast groups");
        }

        // Set buffer size if specified
        if let Some(_size) = buffer_size {
            // Note: neli doesn't expose socket buffer size setting directly
            // This would need to be implemented using raw socket operations
            log::warn!("Buffer size setting not yet implemented in neli");
        }

        // Spawn background thread for event monitoring
        thread::spawn(move || {
            if debug {
                log::info!("Event monitoring thread started");
            }
            
            loop {
                match Self::receive_event(&mut event_socket, debug) {
                    Ok(event) => {
                        if debug {
                            log::debug!("Received event: {:?}", event.event_type);
                        }
                        if let Err(_) = tx.send(event) {
                            // Receiver was dropped, exit the thread
                            if debug {
                                log::info!("Event monitoring thread exiting - receiver dropped");
                            }
                            break;
                        }
                    }
                    Err(e) => {
                        log::error!("Error receiving event: {}", e);
                        // Continue trying to receive events
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Receive a single event from the netlink socket.
    /// This is a blocking operation.
    fn receive_event(socket: &mut NlSocketHandle, debug: bool) -> Result<ConntrackEvent> {
        let (recv_iter, _) = socket
            .recv::<CtNetlinkMessage, Genlmsghdr<u8, ConntrackAttr>>()?;

        for result in recv_iter {
            let result: Nlmsghdr<CtNetlinkMessage, Genlmsghdr<u8, ConntrackAttr>> = result?;
            
            if debug {
                log::debug!("Received netlink message type: {:?}", result.nl_type());
            }
            
            if let NlPayload::Payload(message) = result.nl_payload() {
                let handle = message.attrs().get_attr_handle();
                let flow = Flow::decode(handle)?;
                
                if debug {
                    log::debug!("Received Netlink message type: {:?}", result.nl_type());
                    log::debug!("Flow ID: {:?}", flow.id);
                    log::debug!("Flow status: {:?}", flow.status);
                }
                
                // Determine event type based on message type and status flags
                let event_type = match result.nl_type() {
                    CtNetlinkMessage::ConntrackNew => {
                        // For NEW messages, check if this is actually an UPDATE based on status
                        if let Some(status) = &flow.status {
                            if status.contains(&"StatusSeenReply".to_string()) {
                                ConntrackEventType::Update
                            } else {
                                ConntrackEventType::New
                            }
                        } else {
                            ConntrackEventType::New
                        }
                    },
                    CtNetlinkMessage::ConntrackUpdate => ConntrackEventType::Update,
                    CtNetlinkMessage::ConntrackDestroy => ConntrackEventType::Destroy,
                    _ => {
                        if debug {
                            log::debug!("Skipping unknown message type: {:?}", result.nl_type());
                        }
                        // Skip unknown message types
                        continue;
                    }
                };

                if debug {
                    log::debug!("Decoded event type: {:?}", event_type);
                }

                return Ok(ConntrackEvent {
                    event_type,
                    flow,
                    timestamp: chrono::Utc::now(),
                });
            }
        }

        Err(Error::NoData)
    }

    /// Monitor events with a callback function.
    /// This is a convenience method that handles the channel internally.
    /// 
    /// # Arguments
    /// * `event_mask` - Which events to monitor
    /// * `buffer_size` - Optional netlink socket buffer size
    /// * `debug` - Enable debug output
    /// * `callback` - Function to call for each event
    /// 
    /// # Example
    /// ```rust
    /// use conntrack::*;
    /// 
    /// let mut ct = Conntrack::connect()?;
    /// let event_mask = EventMask::new_only();
    /// 
    /// ct.monitor_events_with_callback(event_mask, None, false, |event| {
    ///     println!("New connection: {:?}", event.flow);
    /// })?;
    /// ```
    pub fn monitor_events_with_callback<F>(
        &mut self,
        event_mask: EventMask,
        buffer_size: Option<usize>,
        debug: bool,
        mut callback: F,
    ) -> Result<()>
    where
        F: FnMut(ConntrackEvent) + Send + 'static,
    {
        let receiver = self.monitor_events(event_mask, buffer_size, debug)?;
        
        thread::spawn(move || {
            for event in receiver {
                callback(event);
            }
        });

        Ok(())
    }
}
