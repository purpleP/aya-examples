#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{kprobe, kretprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

use bindings::{sock, sock_common};

use tcpconnect_common::{Filter, TcpInfo};

#[map]
pub static DATA: PerfEventArray<TcpInfo> = PerfEventArray::new(0);

#[map]
pub static CURRENT_SOCKETS: HashMap<u32, Wrapper> = HashMap::with_max_entries(9, 0);

pub struct Wrapper(*mut sock);

unsafe impl Send for Wrapper {}
unsafe impl Sync for Wrapper {}

#[no_mangle]
static FILTER: Filter = Filter {
    pid: None,
    daddr: None,
    port: None,
};

#[kprobe(name = "tcp_v4_connect_entry")]
pub fn tcp_v4_connect_entry(ctx: ProbeContext) -> i64 {
    match try_tcp_v4_connect_entry(ctx) {
        Ok(ret) => ret,
        Err(err) => err,
    }
}

fn try_tcp_v4_connect_entry(ctx: ProbeContext) -> Result<i64, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let sock: *mut sock = ctx.arg(0).ok_or(1i64)?;
    CURRENT_SOCKETS.insert(&pid, &Wrapper(sock), 0)?;
    Ok(0)
}

#[kretprobe(name = "tcp_v4_connect_return")]
pub fn tcp_v4_connect_return(ctx: ProbeContext) -> i64 {
    match try_tcp_v4_connect_return(ctx) {
        Ok(ret) => ret,
        Err(err) => err,
    }
}

pub fn try_tcp_v4_connect_return(ctx: ProbeContext) -> Result<i64, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let ret: i64 = ctx.ret().ok_or(1)?;
    if ret != 0 {
        return Err(0);
    }
    let socket_wrapper = unsafe { CURRENT_SOCKETS.get(&pid) };
    let sock = socket_wrapper.ok_or(0)?.0;
    CURRENT_SOCKETS.remove(&pid)?;
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
