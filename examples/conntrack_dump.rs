use conntrack::{model::IpProto, *};
use env_logger::Env;

/// This example enables logging, connects to netfilter via socket, dumps
/// conntrack tables, and iterates and logs each flow within the table.
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let env = Env::default()
        .filter_or("RUST_LOG", "info")
        .write_style_or("RUST_LOG_STYLE", "always");

    env_logger::init_from_env(env);

    // Create the Conntrack table via netfilter socket syscall
    let mut builder = DirFilterBuilder::default();
    builder.l4_proto(IpProto::Icmp).icmp_type(8).icmp_code(0);
    let mut filter = Filter::default();
    filter.orig(builder.build()?);
    let mut ct = Conntrack::connect()?.filter(filter);

    // Dump conntrack table as a Vec<Flow>
    let flows = ct.dump()?;

    log::info!("flows: {}", flows.len());
    for flow in flows {
        log::debug!("{flow:?}");
    }

    Ok(())
}
