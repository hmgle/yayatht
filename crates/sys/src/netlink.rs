use std::ffi::CString;
use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NLMSG_ALIGNTO: usize = 4;
const RTA_ALIGNTO: usize = 4;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;
const NLMSG_ERROR: u16 = 2;
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const IFLA_ADDRESS: u16 = 1;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;

#[repr(C)]
#[derive(Clone, Copy)]
struct NlHeader {
    length: u32,
    message_type: u16,
    flags: u16,
    sequence: u32,
    pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfInfo {
    family: u8,
    pad: u8,
    kind: u16,
    index: i32,
    flags: u32,
    change: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfAddr {
    family: u8,
    prefix_len: u8,
    flags: u8,
    scope: u8,
    index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RouteMessage {
    family: u8,
    destination_len: u8,
    source_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    kind: u8,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtAttr {
    length: u16,
    kind: u16,
}

fn align(value: usize, to: usize) -> usize {
    (value + to - 1) & !(to - 1)
}

fn append_struct<T: Copy>(out: &mut Vec<u8>, value: &T) {
    let start = out.len();
    out.resize(start + size_of::<T>(), 0);
    // SAFETY: destination has size_of::<T>() writable bytes and T is Copy.
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::from_ref(value).cast::<u8>(),
            out[start..].as_mut_ptr(),
            size_of::<T>(),
        );
    }
}

fn append_attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) -> io::Result<()> {
    let length = size_of::<RtAttr>() + value.len();
    let length = u16::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "netlink attribute too large"))?;
    append_struct(out, &RtAttr { length, kind });
    out.extend_from_slice(value);
    out.resize(align(out.len(), RTA_ALIGNTO), 0);
    Ok(())
}

struct RouteSocket {
    fd: OwnedFd,
    sequence: u32,
}

impl RouteSocket {
    fn open() -> io::Result<Self> {
        // SAFETY: socket arguments are valid Linux netlink constants.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a newly owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: an all-zero sockaddr_nl is valid before setting family.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: address is a valid sockaddr_nl.
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::from_ref(&address).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, sequence: 0 })
    }

    fn request<T: Copy>(
        &mut self,
        message_type: u16,
        flags: u16,
        body: &T,
        attributes: &[(u16, &[u8])],
    ) -> io::Result<()> {
        self.sequence = self.sequence.wrapping_add(1);
        let mut packet = Vec::with_capacity(128);
        append_struct(
            &mut packet,
            &NlHeader {
                length: 0,
                message_type,
                flags: NLM_F_REQUEST | NLM_F_ACK | flags,
                sequence: self.sequence,
                pid: 0,
            },
        );
        append_struct(&mut packet, body);
        for (kind, value) in attributes {
            append_attr(&mut packet, *kind, value)?;
        }
        packet.resize(align(packet.len(), NLMSG_ALIGNTO), 0);
        let length = u32::try_from(packet.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "netlink message too large")
        })?;
        packet[0..4].copy_from_slice(&length.to_ne_bytes());
        // SAFETY: an all-zero sockaddr_nl addresses the kernel after family.
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: packet and kernel address remain valid during sendto.
        if unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                std::ptr::from_ref(&kernel).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
        self.wait_ack()
    }

    fn wait_ack(&self) -> io::Result<()> {
        let mut buffer = [0u8; 8192];
        loop {
            // SAFETY: buffer is writable for recv.
            let count = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if count == -1 {
                return Err(io::Error::last_os_error());
            }
            let count = count as usize;
            let mut offset = 0;
            while offset + size_of::<NlHeader>() <= count {
                // SAFETY: bounds ensure a complete possibly unaligned header.
                let header = unsafe {
                    std::ptr::read_unaligned(buffer[offset..].as_ptr().cast::<NlHeader>())
                };
                let length = header.length as usize;
                if length < size_of::<NlHeader>() || offset + length > count {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid netlink reply",
                    ));
                }
                if header.sequence == self.sequence && header.message_type == NLMSG_ERROR {
                    let error_offset = offset + size_of::<NlHeader>();
                    if error_offset + size_of::<i32>() > offset + length {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "short netlink error",
                        ));
                    }
                    let error = i32::from_ne_bytes(
                        buffer[error_offset..error_offset + 4]
                            .try_into()
                            .expect("bounded netlink error"),
                    );
                    return if error == 0 {
                        Ok(())
                    } else {
                        Err(io::Error::from_raw_os_error(-error))
                    };
                }
                offset += align(length, NLMSG_ALIGNTO);
            }
        }
    }
}

pub fn interface_index(name: &str) -> io::Result<u32> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL"))?;
    // SAFETY: name is NUL-terminated.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}

fn set_link_up(socket: &mut RouteSocket, index: u32, mac: Option<[u8; 6]>) -> io::Result<()> {
    let body = IfInfo {
        family: libc::AF_UNSPEC as u8,
        pad: 0,
        kind: 0,
        index: index as i32,
        flags: libc::IFF_UP as u32,
        change: libc::IFF_UP as u32,
    };
    let mac_bytes = mac.unwrap_or_default();
    let attributes: Vec<(u16, &[u8])> = if mac.is_some() {
        vec![(IFLA_ADDRESS, &mac_bytes)]
    } else {
        Vec::new()
    };
    socket.request(RTM_NEWLINK, 0, &body, &attributes)
}

fn add_address(
    socket: &mut RouteSocket,
    index: u32,
    family: u8,
    prefix_len: u8,
    address: &[u8],
) -> io::Result<()> {
    let body = IfAddr {
        family,
        prefix_len,
        flags: if family == libc::AF_INET6 as u8 {
            0x02
        } else {
            0
        },
        scope: 0,
        index,
    };
    socket.request(
        RTM_NEWADDR,
        NLM_F_CREATE | NLM_F_EXCL,
        &body,
        &[(IFA_LOCAL, address), (IFA_ADDRESS, address)],
    )
}

fn add_default_route(
    socket: &mut RouteSocket,
    index: u32,
    family: u8,
    gateway: &[u8],
) -> io::Result<()> {
    let body = RouteMessage {
        family,
        destination_len: 0,
        source_len: 0,
        tos: 0,
        table: 254,
        protocol: 3,
        scope: 0,
        kind: 1,
        flags: 0,
    };
    socket.request(
        RTM_NEWROUTE,
        NLM_F_CREATE | NLM_F_EXCL,
        &body,
        &[(RTA_GATEWAY, gateway), (RTA_OIF, &index.to_ne_bytes())],
    )
}

pub fn configure_namespace(
    tap_name: &str,
    tap_mac: [u8; 6],
    ipv4: Option<(Ipv4Addr, u8, Ipv4Addr)>,
    ipv6: Option<(Ipv6Addr, u8, Ipv6Addr)>,
) -> io::Result<()> {
    let mut socket = RouteSocket::open()?;
    let loopback = interface_index("lo")?;
    set_link_up(&mut socket, loopback, None)?;
    let tap = interface_index(tap_name)?;
    set_link_up(&mut socket, tap, Some(tap_mac))?;
    if let Some((address, prefix, gateway)) = ipv4 {
        add_address(
            &mut socket,
            tap,
            libc::AF_INET as u8,
            prefix,
            &address.octets(),
        )?;
        add_default_route(&mut socket, tap, libc::AF_INET as u8, &gateway.octets())?;
    }
    if let Some((address, prefix, gateway)) = ipv6 {
        add_address(
            &mut socket,
            tap,
            libc::AF_INET6 as u8,
            prefix,
            &address.octets(),
        )?;
        add_default_route(&mut socket, tap, libc::AF_INET6 as u8, &gateway.octets())?;
    }
    Ok(())
}
