#![no_std]

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct TcpInfo {
    pub pid: u32,
    pub comm: [u8; 16],
    pub saddr: u32,
    pub daddr: u32,
    pub lport: u16,
    pub dport: u16,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Filter {
    pub pid: Option<u32>,
    pub daddr: Option<u32>,
    pub port: Option<u16>,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for TcpInfo {}
    unsafe impl aya::Pod for Filter {}
}
