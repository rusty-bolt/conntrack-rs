use conntrack::*;
use env_logger::Env;
use std::env;

/// This example demonstrates real-time conntrack event monitoring.
/// It's equivalent to running `conntrack -E` from the command line.
/// 
/// Usage: conntrack-events [-d|--debug]
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let debug = args.iter().any(|arg| arg == "-d" || arg == "--debug");
    
    let log_level = if debug { "debug" } else { "info" };
    let env = Env::default()
        .filter_or("RUST_LOG", log_level)
        .write_style_or("RUST_LOG_STYLE", "always");

    env_logger::init_from_env(env);

    log::info!("Starting conntrack event monitoring...");
    log::info!("This is equivalent to running 'conntrack -E'");
    if debug {
        log::info!("Debug mode enabled");
    }
    log::info!("Press Ctrl+C to stop");

    // Create the Conntrack instance
    let mut ct = Conntrack::connect()?;

    // Monitor all events (NEW, UPDATE, DESTROY)
    let event_mask = EventMask::all();
    let receiver = ct.monitor_events(event_mask, None, debug)?;

    let mut event_count = 0;

    // Process events as they come in
    for event in receiver {
        event_count += 1;
        
        match event.event_type {
            ConntrackEventType::New => {
                log::info!("[{}] NEW connection:", event_count);
            }
            ConntrackEventType::Update => {
                log::info!("[{}] UPDATE connection:", event_count);
            }
            ConntrackEventType::Destroy => {
                log::info!("[{}] DESTROY connection:", event_count);
            }
        }

        // Print connection details
        if let Some(origin) = &event.flow.origin {
            if let Some(src) = origin.src {
                if let Some(dst) = origin.dst {
                    if let Some(proto) = &origin.proto {
                        match proto.number {
                            Some(IpProto::Icmp) => {
                                // ICMP connection
                                if let Some(icmp_id) = proto.icmp_id {
                                    if let Some(icmp_type) = proto.icmp_type {
                                        if let Some(icmp_code) = proto.icmp_code {
                                            log::info!(
                                                "  {} -> {} icmp type={} code={} id={}",
                                                src, dst, icmp_type, icmp_code, icmp_id
                                            );
                                        }
                                    }
                                }
                            }
                            _ => {
                                // Check for ICMPv6 first
                                if let Some(icmpv6_id) = proto.icmpv6_id {
                                    if let Some(icmpv6_type) = proto.icmpv6_type {
                                        if let Some(icmpv6_code) = proto.icmpv6_code {
                                            log::info!(
                                                "  {} -> {} icmpv6 type={} code={} id={}",
                                                src, dst, icmpv6_type, icmpv6_code, icmpv6_id
                                            );
                                        }
                                    }
                                } else if let Some(src_port) = proto.src_port {
                                    if let Some(dst_port) = proto.dst_port {
                                        // Get protocol number for display
                                        let proto_num = match proto.number {
                                            Some(IpProto::Tcp) => 6,
                                            Some(IpProto::Udp) => 17,
                                            Some(IpProto::Icmp) => 1,
                                            Some(IpProto::Dccp) => 33,
                                            Some(IpProto::Sctp) => 132,
                                            Some(IpProto::Udplite) => 136,
                                            Some(IpProto::Gre) => 47,
                                            Some(IpProto::Esp) => 50,
                                            Some(IpProto::Ah) => 51,
                                            _ => 0,
                                        };
                                        log::info!(
                                            "  {}:{} -> {}:{} (proto: {})",
                                            src, src_port, dst, dst_port, proto_num
                                        );
                                    }
                                } else {
                                    log::info!(
                                        "  {} -> {} (proto: {:?})",
                                        src, dst, proto.number
                                    );
                                }
                            }
                        }
                    } else {
                        log::info!("  {} -> {}", src, dst);
                    }
                }
            }
        }

        // Print reply connection details if available
        if let Some(reply) = &event.flow.reply {
            if let Some(src) = reply.src {
                if let Some(dst) = reply.dst {
                    if let Some(proto) = &reply.proto {
                        match proto.number {
                            Some(IpProto::Icmp) => {
                                if let Some(icmp_id) = proto.icmp_id {
                                    if let Some(icmp_type) = proto.icmp_type {
                                        if let Some(icmp_code) = proto.icmp_code {
                                            log::info!(
                                                "  [REPLY] {} -> {} icmp type={} code={} id={}",
                                                src, dst, icmp_type, icmp_code, icmp_id
                                            );
                                        }
                                    }
                                }
                            }
                            _ => {
                                // Check for ICMPv6 first
                                if let Some(icmpv6_id) = proto.icmpv6_id {
                                    if let Some(icmpv6_type) = proto.icmpv6_type {
                                        if let Some(icmpv6_code) = proto.icmpv6_code {
                                            log::info!(
                                                "  [REPLY] {} -> {} icmpv6 type={} code={} id={}",
                                                src, dst, icmpv6_type, icmpv6_code, icmpv6_id
                                            );
                                        }
                                    }
                                } else if let Some(src_port) = proto.src_port {
                                    if let Some(dst_port) = proto.dst_port {
                                        log::info!(
                                            "  [REPLY] {}:{} -> {}:{}",
                                            src, src_port, dst, dst_port
                                        );
                                    }
                                } else {
                                    log::info!("  [REPLY] {} -> {}", src, dst);
                                }
                            }
                        }
                    } else {
                        log::info!("  [REPLY] {} -> {}", src, dst);
                    }
                }
            }
        }

        // Print TCP state information
        if let Some(proto_info) = &event.flow.proto_info {
            if let Some(tcp_info) = &proto_info.tcp {
                if let Some(state) = &tcp_info.state {
                    log::info!("  TCP State: {:?}", state);
                }
            }
        }

        // Print additional flow information
        if let Some(status) = &event.flow.status {
            log::info!("  Status: {:?}", status);
            
            // Check for UNREPLIED status (indicates NEW event)
            if status.contains(&"StatusSeenReply".to_string()) {
                log::info!("  [REPLIED]");
            } else {
                log::info!("  [UNREPLIED]");
            }
            
            // Check for ASSURED status
            if status.contains(&"StatusAssured".to_string()) {
                log::info!("  [ASSURED]");
            }
        }
        
        if let Some(timeout) = event.flow.timeout {
            log::info!("  Timeout: {:?}", timeout);
        }

        // Print byte and packet counters if available
        if let Some(counter_origin) = &event.flow.counter_origin {
            if let Some(packets) = counter_origin.packets {
                if let Some(bytes) = counter_origin.bytes {
                    log::info!("  Origin: {} packets, {} bytes", packets, bytes);
                }
            }
        }
        if let Some(counter_reply) = &event.flow.counter_reply {
            if let Some(packets) = counter_reply.packets {
                if let Some(bytes) = counter_reply.bytes {
                    log::info!("  Reply: {} packets, {} bytes", packets, bytes);
                }
            }
        }

        log::info!("  Timestamp: {}", event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"));
        
        // Show raw flow data in debug mode
        if debug {
            log::debug!("  Raw flow data: {:#?}", event.flow);
        }
        
        log::info!("");
    }

    Ok(())
}
