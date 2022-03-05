#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use std::net::Ipv4Addr;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Data {
    pub port: u16,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct LogEvent {
    pub src_addr: BeIpv4Addr,
    pub src_port: u16,
    pub dest_addr: BeIpv4Addr,
    pub dest_port: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct BeIpv4Addr(u32);

impl BeIpv4Addr {
    /// Conversion from `BeIpv4Addr` to `std::net::Ipv4Addr`.
    #[cfg(feature = "std")]
    pub fn to_ip(self) -> Ipv4Addr {
        // Network order for the IP address will represent `127.0.0.1` as `[1, 0, 0, 127]`. We
        // need to reverse the byte order before creating the `Ipv4Addr`.
        self.0.swap_bytes().into()
    }
}

/// Conversion from `u32` to `BeIpv4Addr`.
impl From<u32> for BeIpv4Addr {
    fn from(be: u32) -> Self {
        Self(be)
    }
}

/// Conversion from `Ipv4Addr` to `BeIpv4Addr`
#[cfg(feature = "std")]
impl From<Ipv4Addr> for BeIpv4Addr {
    fn from(ip: Ipv4Addr) -> Self {
        Self(u32::from_be_bytes(ip.octets()).swap_bytes())
    }
}