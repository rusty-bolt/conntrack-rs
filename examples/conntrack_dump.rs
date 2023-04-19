use conntrack::*;
use env_logger::Env;

/// This example enables logging, connects to netfilter via socket, dumps
/// conntrack tables, and iterates and logs each flow within the table.
fn main() -> Result<()> {
    let env = Env::default()
        .filter_or("RUST_LOG", "info")
        .write_style_or("RUST_LOG_STYLE", "always");

    env_logger::init_from_env(env);

    // Create the Conntrack table via netfilter socket syscall
    let mut ct = Conntrack::connect()?;

    // Dump conntrack table as a Vec<Flow>
    let flows = ct.dump()?;

    for flow in flows {
        log::info!("{flow:?}");
    }

    Ok(())
}
