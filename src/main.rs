use std::{env, time};
use std::process;

use futures::stream::StreamExt;
use port_blocker::Data;
use probes::port_blocker;
use probes::port_blocker::LogEvent;
use redbpf::{Array, load::Loaded, load::Loader, Map, xdp};
use tokio::signal;
use tracing::error;

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/target/bpf/programs/port_blocker/port_blocker.elf"
    ))
}

const PORTS_ARRAY_NAME: &str = "ports";
const PORTS_ARRAY_PIN_FILE: &str = "/sys/fs/bpf/ports";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let xdp_mode = xdp::Flags::SkbMode;

    let ports = env::args()
        .skip(1)
        .map(|s| {
            s.parse::<u16>()
                .expect(format!("Unable to convert {} to u16", s).as_str())
        })
        .collect::<Vec<u16>>();

    if ports.is_empty() {
        error!("Specify port numbers to block");
        process::exit(1);
    }

    println!("Ports will be blocked: {:?}", ports);

    // TODO: move to arguments?
    let interface = "lo";

    let loaded = Loader::load(probe_code())
        .map_err(|err| format!("{:?}", err))?;

    let Loaded { mut events, mut module } = loaded;

    // pin ports array to sys fs
    module.map_mut(PORTS_ARRAY_NAME).expect("Can't find ports map")
        .pin(PORTS_ARRAY_PIN_FILE)
        .expect("error on pinning");

    // attach xdp program
    for xdp in module.xdps_mut() {
        xdp.attach_xdp(interface, xdp_mode)
            .map_err(|err| format!("Attach error: {:?}", err))?;
        println!("Attach port blocker on interface: {} with mode {:?}", interface, xdp_mode);
    }

    // fill ports
    let ports_array_map = Map::from_pin_file(PORTS_ARRAY_PIN_FILE).expect("error on Map::from_pin_file");
    let ports_array = Array::<Data>::new(&ports_array_map).expect("error on creating ports array");

    for (index, port) in ports.iter().enumerate() {
        let data = Data { port: port.clone() };
        ports_array.set(index as u32, data).expect("Can't add port to ports array");
    }

    // print events from xdp program
    tokio::spawn(async move {
        while let Some((name, events)) = events.next().await {
            for event in events {
                match name.as_str() {
                    "log_events" => {
                        let log_value = unsafe {
                            std::ptr::read(event.as_ptr() as *const LogEvent)
                        };
                        println!(
                            "Blocked port event. From: {}:{} to {}:{}",
                            log_value.src_addr.to_ip(),
                            log_value.src_port,
                            log_value.dest_addr.to_ip(),
                            log_value.dest_port
                        );
                    }

                    _ => println!("unexpected event"),
                }
            }
        }
    });

    loop {
        //println!("Port counter: {}", ports_array.get(0).unwrap().port);
        tokio::select! {
            _ = tokio::time::sleep(time::Duration::from_secs(1)) => {}
            _ = signal::ctrl_c() => {
                break;
            }
        }
    }

    println!("Port blocker is completed.");

    // unpin ports array from sys fs
    module.map_mut(PORTS_ARRAY_NAME).expect("Can't find ports map")
        .unpin()
        .expect("error on unpinning");

    // de-attach xdp program
    for xdp in module.xdps_mut() {
        println!("DeAttach xdp program {} on interface {}", xdp.name(), interface);
        let _ = xdp.detach_xdp(interface)
            .map_err(|err| format!("DeAttach error: {:?}", err))?;
    }

    return Ok(());
}
