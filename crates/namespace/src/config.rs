use std::ffi::OsString;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use thiserror::Error;
use yayatht_packet::MacAddress;
use yayatht_proxy_proto::{Credentials, Protocol};

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

    #[must_use]
    pub fn dataplane(
        &self,
        upstream: &UpstreamConfig,
        max_tcp_flows: usize,
        max_pending_tcp_bytes: usize,
        max_retained_tcp_bytes: usize,
        tcp_receive_buffer_bytes: usize,
        tcp_send_buffer_bytes: usize,
    ) -> yayatht_dataplane::reactor::Config {
        yayatht_dataplane::reactor::Config {
            target_mac: self.target_mac,
            gateway_mac: self.gateway_mac,
            target_ipv4: self.target_ipv4.map(|(address, _)| address),
            gateway_ipv4: self.gateway_ipv4,
            target_ipv6: self.target_ipv6.map(|(address, _)| address),
            gateway_ipv6: self.gateway_ipv6,
            tap_mtu: self.tap_mtu,
            tap_offload: self.tap_offload,
            upstream: match upstream {
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
            max_tcp_flows,
            max_pending_tcp_bytes,
            max_retained_tcp_bytes,
            tcp_receive_buffer_bytes,
            tcp_send_buffer_bytes,
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
    pub max_tcp_flows: usize,
    pub max_pending_tcp_bytes: usize,
    pub max_retained_tcp_bytes: usize,
    pub tcp_receive_buffer_bytes: usize,
    pub tcp_send_buffer_bytes: usize,
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
