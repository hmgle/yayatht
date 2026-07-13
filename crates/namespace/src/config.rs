use std::ffi::OsString;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use thiserror::Error;
use yayatht_packet::MacAddress;

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub interface_name: String,
    pub target_mac: MacAddress,
    pub gateway_mac: MacAddress,
    pub target_ipv4: Option<(Ipv4Addr, u8)>,
    pub gateway_ipv4: Option<Ipv4Addr>,
    pub target_ipv6: Option<(Ipv6Addr, u8)>,
    pub gateway_ipv6: Option<Ipv6Addr>,
}

impl NetworkConfig {
    #[must_use]
    pub fn synthetic(ipv4: bool, ipv6: bool) -> Self {
        Self {
            interface_name: "eth0".to_owned(),
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
        host_loopback: bool,
        max_tcp_flows: usize,
    ) -> yayatht_dataplane::reactor::Config {
        yayatht_dataplane::reactor::Config {
            target_mac: self.target_mac,
            gateway_mac: self.gateway_mac,
            target_ipv4: self.target_ipv4.map(|(address, _)| address),
            gateway_ipv4: self.gateway_ipv4,
            target_ipv6: self.target_ipv6.map(|(address, _)| address),
            gateway_ipv6: self.gateway_ipv6,
            host_loopback,
            max_tcp_flows,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LaunchConfig {
    pub command: Vec<OsString>,
    pub name: Option<String>,
    pub runtime_root: Option<PathBuf>,
    pub network: NetworkConfig,
    pub host_loopback: bool,
    pub max_tcp_flows: usize,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("target command is empty")]
    EmptyCommand,
    #[error("at least one IP family must be enabled")]
    NoIpFamily,
    #[error("max_tcp_flows must be between 1 and 1048576")]
    InvalidFlowLimit,
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
        if !(1..=1_048_576).contains(&self.max_tcp_flows) {
            return Err(ConfigError::InvalidFlowLimit);
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
}
