#![no_std]
#![no_main]

use probes::port_blocker::{BeIpv4Addr, Data, LogEvent};
use redbpf_probes::maps::Array;
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

const MAX_SIZE: u32 = 10;

#[map(link_section = "maps/ports")]
static mut PORTS: Array<Data> = Array::with_max_entries(MAX_SIZE);

#[map(link_section = "maps/log_events")]
static mut LOG_EVENTS: PerfMap<LogEvent> = PerfMap::with_max_entries(512);

#[xdp]
pub fn block_port(ctx: XdpContext) -> XdpResult {
    if let Ok(transport) = ctx.transport() {
        unsafe {
            for index in 0..MAX_SIZE {
                let data = PORTS.get(index);

                if data.is_some() {
                    if transport.dest() == data.unwrap().port {
                        bpf_trace_printk(b"Drop packet\0");

                        // parse ip
                        let ip = ctx.ip();
                        let (_src_ip, _dst_ip): (BeIpv4Addr, BeIpv4Addr) = match ip {
                            Ok(ip_header) => ((*ip_header).saddr.into(), (*ip_header).daddr.into()),
                            Err(_) => panic!("Can't parse ip header!")
                        };

                        let event = LogEvent {
                            src_addr: _src_ip,
                            src_port: transport.source(),
                            dest_addr: _dst_ip,
                            dest_port: transport.dest(),

                        };
                        LOG_EVENTS.insert(&ctx, &MapData::new(event));

                        return Ok(XdpAction::Drop);
                    }
                }
            }
        }
    }

    Ok(XdpAction::Pass)
}