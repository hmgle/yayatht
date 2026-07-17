use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use thiserror::Error;
use yayatht_packet::MacAddress;
use yayatht_proxy_proto::{Credentials, Protocol};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxConfig {
    On,
    Off,
}

impl SandboxConfig {
    #[must_use]
    pub const fn enabled(self) -> bool {
        matches!(self, Self::On)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsMode {
    ProxyTcp,
    Off,
}

#[derive(Clone, Debug)]
pub struct DnsConfig {
    pub mode: DnsMode,
    /// Resolver the intercepted queries are forwarded to. `None` with
    /// `ProxyTcp` keeps interception active but answers SERVFAIL, so a
    /// missing host resolver never leaks queries or blocks TCP workloads.
    pub upstream: Option<SocketAddr>,
}

impl DnsConfig {
    #[must_use]
    pub fn off() -> Self {
        Self {
            mode: DnsMode::Off,
            upstream: None,
        }
    }
}

/// Returns the first `nameserver` address in `resolv.conf` contents.
#[must_use]
pub fn first_nameserver(resolv_conf: &str) -> Option<IpAddr> {
    resolv_conf
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("nameserver"))
                .then(|| fields.next())
                .flatten()
        })
        .find_map(|value| value.parse().ok())
}

#[derive(Clone, Debug)]
pub enum UpstreamConfig {
    Direct {
        host_loopback: bool,
    },
    Proxy {
        protocol: Protocol,
        address: SocketAddr,
        credentials: Option<Credentials>,
    },
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub interface_name: String,
    pub tap_mtu: u32,
    pub tap_offload: bool,
    pub target_mac: MacAddress,
    pub gateway_mac: MacAddress,
    pub target_ipv4: Option<(Ipv4Addr, u8)>,
    pub gateway_ipv4: Option<Ipv4Addr>,
    pub target_ipv6: Option<(Ipv6Addr, u8)>,
    pub gateway_ipv6: Option<Ipv6Addr>,
}

impl NetworkConfig {
    #[must_use]
    pub fn synthetic(ipv4: bool, ipv6: bool, tap_mtu: u32, tap_offload: bool) -> Self {
        Self {
            interface_name: "eth0".to_owned(),
            tap_mtu,
            tap_offload,
            target_mac: MacAddress([0x02, 0x79, 0x61, 0x79, 0x61, 0x02]),
            gateway_mac: MacAddress([0x02, 0x79, 0x61, 0x79, 0x61, 0x01]),
            target_ipv4: ipv4.then_some((Ipv4Addr::new(192, 0, 2, 2), 24)),
            gateway_ipv4: ipv4.then_some(Ipv4Addr::new(192, 0, 2, 1)),
            target_ipv6: ipv6.then_some((
                "fd79:6179:6174:6874::2"
                    .parse()
                    .expect("constant IPv6 address"),
                64,
            )),
            gateway_ipv6: ipv6.then_some(
                "fd79:6179:6174:6874::1"
                    .parse()
                    .expect("constant IPv6 address"),
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LaunchConfig {
    pub command: Vec<OsString>,
    pub name: Option<String>,
    pub runtime_root: Option<PathBuf>,
    pub network: NetworkConfig,
    pub upstream: UpstreamConfig,
    pub dns: DnsConfig,
    pub sandbox: SandboxConfig,
    pub max_tcp_flows: usize,
    pub max_pending_tcp_bytes: usize,
    pub max_retained_tcp_bytes: usize,
    pub tcp_receive_buffer_bytes: usize,
    pub tcp_send_buffer_bytes: usize,
}

impl LaunchConfig {
    #[must_use]
    pub fn dataplane(&self) -> yayatht_dataplane::reactor::Config {
        yayatht_dataplane::reactor::Config {
            target_mac: self.network.target_mac,
            gateway_mac: self.network.gateway_mac,
            target_ipv4: self.network.target_ipv4.map(|(address, _)| address),
            gateway_ipv4: self.network.gateway_ipv4,
            target_ipv6: self.network.target_ipv6.map(|(address, _)| address),
            gateway_ipv6: self.network.gateway_ipv6,
            tap_mtu: self.network.tap_mtu,
            tap_offload: self.network.tap_offload,
            upstream: match &self.upstream {
                UpstreamConfig::Direct { host_loopback } => {
                    yayatht_dataplane::reactor::Upstream::Direct {
                        host_loopback: *host_loopback,
                    }
                }
                UpstreamConfig::Proxy {
                    protocol,
                    address,
                    credentials,
                } => yayatht_dataplane::reactor::Upstream::Proxy {
                    protocol: *protocol,
                    address: *address,
                    credentials: credentials.clone(),
                },
            },
            dns_proxy_tcp: self.dns.mode == DnsMode::ProxyTcp,
            dns_upstream: self.dns.upstream,
            max_tcp_flows: self.max_tcp_flows,
            max_pending_tcp_bytes: self.max_pending_tcp_bytes,
            max_retained_tcp_bytes: self.max_retained_tcp_bytes,
            tcp_receive_buffer_bytes: self.tcp_receive_buffer_bytes,
            tcp_send_buffer_bytes: self.tcp_send_buffer_bytes,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("target command is empty")]
    EmptyCommand,
    #[error("at least one IP family must be enabled")]
    NoIpFamily,
    #[error("max_tcp_flows must be between 1 and 1048576")]
    InvalidFlowLimit,
    #[error("global TCP byte limits must be between 16384 and 1 TiB")]
    InvalidGlobalByteLimit,
    #[error("per-flow TCP socket buffers must be between 16384 and 16 MiB")]
    InvalidSocketBufferLimit,
    #[error("tap_mtu must be between 1280 and 65520")]
    InvalidTapMtu,
    #[error("instance name must match [A-Za-z0-9_.-]+")]
    InvalidName,
}

impl LaunchConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.command.is_empty() {
            return Err(ConfigError::EmptyCommand);
        }
        if self.network.target_ipv4.is_none() && self.network.target_ipv6.is_none() {
            return Err(ConfigError::NoIpFamily);
        }
        if !(yayatht_sys::tun::MIN_TAP_MTU..=yayatht_sys::tun::MAX_TAP_MTU)
            .contains(&self.network.tap_mtu)
        {
            return Err(ConfigError::InvalidTapMtu);
        }
        if !(1..=1_048_576).contains(&self.max_tcp_flows) {
            return Err(ConfigError::InvalidFlowLimit);
        }
        if !(16 * 1024..=1024usize.pow(4)).contains(&self.max_pending_tcp_bytes)
            || !(16 * 1024..=1024usize.pow(4)).contains(&self.max_retained_tcp_bytes)
        {
            return Err(ConfigError::InvalidGlobalByteLimit);
        }
        if !(16 * 1024..=16 * 1024 * 1024).contains(&self.tcp_receive_buffer_bytes)
            || !(16 * 1024..=16 * 1024 * 1024).contains(&self.tcp_send_buffer_bytes)
        {
            return Err(ConfigError::InvalidSocketBufferLimit);
        }
        if let Some(name) = &self.name
            && (name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)))
        {
            return Err(ConfigError::InvalidName);
        }
        Ok(())
    }

    pub(crate) fn clear_proxy_credentials(&mut self) {
        if let UpstreamConfig::Proxy { credentials, .. } = &mut self.upstream {
            *credentials = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::first_nameserver;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn first_nameserver_skips_comments_and_options() {
        let contents = "# Generated by NetworkManager\n\
                        options edns0 trust-ad\n\
                        search example.net\n\
                        nameserver 192.0.2.53\n\
                        nameserver 192.0.2.54\n";
        assert_eq!(
            first_nameserver(contents),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)))
        );
    }

    #[test]
    fn first_nameserver_accepts_ipv6_and_ignores_garbage() {
        let contents = "nameserver not-an-address\nnameserver 2001:db8::53\n";
        assert_eq!(
            first_nameserver(contents),
            Some(IpAddr::V6("2001:db8::53".parse::<Ipv6Addr>().unwrap()))
        );
    }

    #[test]
    fn first_nameserver_handles_empty_host_files() {
        assert_eq!(first_nameserver("# Generated by NetworkManager\n"), None);
    }
}
