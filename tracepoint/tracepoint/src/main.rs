use aya::programs::BtfTracePoint;
use aya::{include_bytes_aligned, BpfLoader};
use aya::{maps::perf::AsyncPerfEventArray, util::online_cpus};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::warn;
use std::net::Ipv4Addr;
use std::ptr;
use tokio::signal;
use tracepoint_common::{Filter, TcpInfo};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    daddr: Option<String>,
    #[clap(short = 'i', long)]
    pid: Option<String>,
    #[clap(short, long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    let mut bpf = BpfLoader::new();
    let filter_pid = opt.pid.map(|string| string.parse::<u32>().unwrap());

    let filter_daddr = opt
        .daddr
        .map(|string| u32::from_be_bytes(string.parse::<Ipv4Addr>().unwrap().octets()));

    let filter = Filter {
        pid: filter_pid,
        daddr: filter_daddr,
        port: opt.port,
    };

    let bpf = bpf.set_global("FILTER", &filter);
    #[cfg(debug_assertions)]
    let mut bpf = bpf.load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tracepoint"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = bpf.load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tracepoint"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = aya::Btf::from_sys_fs()?;
    let program: &mut BtfTracePoint = bpf.program_mut("tracepoint").unwrap().try_into()?;
    program.load("inet_sock_set_state", &btf)?;
    program.attach()?;

    println!("Waiting for Ctrl-C...");
    println!(
        "{:<6}{:<16}{:<16}{:<6}{:<16}{:<6}",
        "PID", "COMM", "SADDR", "LPORT", "DADDR", "DPORT",
    );
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events = AsyncPerfEventArray::try_from(bpf.map_mut("DATA")?)?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;
        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(9000))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let tcp_info = unsafe { ptr::read_unaligned(buf.as_ptr() as *const TcpInfo) };
                    let command = tcp_info.comm.split(|&ch| ch == 0).next().unwrap();
                    let command = std::str::from_utf8(command).unwrap();
                    println!(
                        "{:<6}{:<16}{:<16}{:<6}{:<16}{:<6}",
                        tcp_info.pid,
                        command,
                        Ipv4Addr::from(tcp_info.saddr),
                        tcp_info.lport,
                        Ipv4Addr::from(tcp_info.daddr),
                        tcp_info.dport,
                    );
                }
            }
        });
    }

    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
