#![no_std]
#![no_main]

use aya_bpf::{
    cty::c_int,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{btf_tracepoint, map},
    maps::PerfEventArray,
    programs::BtfTracePointContext,
};
use aya_log_ebpf::info;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod tcp_states;

use vmlinux::sock;

use tracepoint_common::{Filter, TcpInfo};

use crate::tcp_states::{TCP_CLOSE, TCP_SYN_SENT};
use crate::vmlinux::sock_common;

#[map]
pub static DATA: PerfEventArray<TcpInfo> = PerfEventArray::new(0);

#[no_mangle]
static FILTER: Filter = Filter {
    pid: None,
    daddr: None,
    port: None,
};

#[btf_tracepoint(name = "tracepoint")]
pub fn tracepoint(ctx: BtfTracePointContext) -> i64 {
    match try_tracepoint(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tracepoint(ctx: BtfTracePointContext) -> Result<i64, i64> {
    let old_state: c_int = unsafe { ctx.arg(1) };
    let new_state: c_int = unsafe { ctx.arg(2) };
    if old_state != TCP_CLOSE && new_state != TCP_SYN_SENT {
        return Ok(0);
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let sock: *const sock = unsafe { ctx.arg(0) };
    let sk_common = unsafe { bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)? };
    let saddr = u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr });
    let lport: u16 = u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num });
    let daddr: u32 = u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr });
    let dport: u16 = u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport });
    let filter = unsafe { core::ptr::read_volatile(&FILTER) };
    if let Some(filter_pid) = filter.pid {
        if pid != filter_pid {
            return Ok(0);
        }
    }
    if let Some(filter_daddr) = filter.daddr {
        if daddr != filter_daddr {
            return Ok(0);
        }
    }
    if let Some(filter_port) = filter.port {
        if dport != filter_port {
            return Ok(0);
        }
    }
    let comm = bpf_get_current_comm()?;
    DATA.output(
        &ctx,
        &TcpInfo {
            pid,
            comm,
            saddr,
            lport,
            daddr,
            dport,
        },
        0,
    );
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
