#![no_std]
#![no_main]

use probes::port_blocker::Data;
use redbpf_probes::maps::Array;
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

const MAX_SIZE: u32 = 10;

#[map(link_section = "maps/ports")]
static mut PORTS: Array<Data> = Array::with_max_entries(MAX_SIZE);

#[map(link_section = "maps/log_events")]
static mut LOG_EVENTS: PerfMap<u32> = PerfMap::with_max_entries(512);

#[xdp]
pub fn block_port_80(ctx: XdpContext) -> XdpResult {
    if let Ok(transport) = ctx.transport() {
        /*unsafe {
            log_events.insert(&ctx, &MapData::new(transport.dest() as u32));
        }*/

        unsafe {
            //bpf_trace_printk(b"Port " + PORTS. + " is here\0");
            for index in 0..MAX_SIZE {
                let data = PORTS.get(index);

                if data.is_some() {
                    if transport.dest() == data.unwrap().port {
                        bpf_trace_printk(b"Drop packet\0");
                        return Ok(XdpAction::Drop);
                    }
                }
            }
        }
    }

    Ok(XdpAction::Pass)
}