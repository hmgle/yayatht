use clap::{ArgGroup, Args, Parser, Subcommand};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use yayatht_namespace::{LaunchConfig, NetworkConfig, Supervisor, UpstreamConfig};
use yayatht_proxy_proto::{Credentials, Protocol};

#[derive(Debug, Parser)]
#[command(
    name = "yayatht",
    version,
    about = "Run a command behind a rootless namespace TAP adapter"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run(RunArgs),
    Status(StatusArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("upstream")
        .required(true)
        .multiple(false)
        .args(["direct", "socks5", "http_connect"])
))]
struct RunArgs {
    #[arg(long, help = "Connect namespace TCP flows directly")]
    direct: bool,
    #[arg(
        long,
        value_name = "ADDR",
        help = "Route TCP through a numeric SOCKS5 proxy"
    )]
    socks5: Option<SocketAddr>,
    #[arg(
        long,
        value_name = "ADDR",
        help = "Route TCP through a numeric HTTP CONNECT proxy"
    )]
    http_connect: Option<SocketAddr>,
    #[arg(
        long,
        value_name = "PATH",
        requires = "proxy_password_file",
        help = "Read the proxy username from a protected file"
    )]
    proxy_username_file: Option<PathBuf>,
    #[arg(
        long,
        value_name = "PATH",
        requires = "proxy_username_file",
        help = "Read the proxy password from a protected file"
    )]
    proxy_password_file: Option<PathBuf>,
    #[arg(long)]
    name: Option<String>,
    #[arg(long, value_name = "ROOT")]
    runtime_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 4096)]
    max_tcp_flows: usize,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_pending_tcp_bytes: usize,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_retained_tcp_bytes: usize,
    #[arg(long, default_value_t = 256 * 1024)]
    tcp_receive_buffer_bytes: usize,
    #[arg(long, default_value_t = 256 * 1024)]
    tcp_send_buffer_bytes: usize,
    #[arg(
        long,
        default_value_t = yayatht_sys::tun::DEFAULT_TAP_MTU,
        value_name = "BYTES"
    )]
    tap_mtu: u32,
    #[arg(
        long,
        value_parser = clap::builder::PossibleValuesParser::new(["on", "off"]),
        default_value = "on",
        value_name = "on|off",
        help = "Negotiate TAP vnet_hdr and kernel offloads"
    )]
    tap_offload: String,
    #[arg(long)]
    no_ipv4: bool,
    #[arg(long)]
    no_ipv6: bool,
    #[arg(
        long,
        help = "Map the synthetic gateway to host loopback on the same port"
    )]
    host_loopback: bool,
    #[arg(last = true, required = true, num_args = 1.., allow_hyphen_values = true)]
    command: Vec<OsString>,
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[arg(long)]
    name: String,
    #[arg(long, value_name = "ROOT")]
    runtime_dir: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("yayatht=info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
    let result = match Cli::parse().command {
        Command::Run(args) => run(args),
        Command::Status(args) => status(args),
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("yayatht: {error}");
            std::process::exit(125);
        }
    }
}

fn run(args: RunArgs) -> Result<i32, Box<dyn std::error::Error>> {
    let credentials = match (&args.proxy_username_file, &args.proxy_password_file) {
        (Some(username), Some(password)) => Some(Credentials::new(
            read_credential(username)?,
            read_credential(password)?,
        )?),
        (None, None) => None,
        _ => return Err("proxy username and password files must be provided together".into()),
    };
    let upstream = match (args.direct, args.socks5, args.http_connect) {
        (true, None, None) => {
            if credentials.is_some() {
                return Err("proxy credentials cannot be used with --direct".into());
            }
            UpstreamConfig::Direct {
                host_loopback: args.host_loopback,
            }
        }
        (false, Some(address), None) => {
            if args.host_loopback {
                return Err("--host-loopback is only valid with --direct".into());
            }
            UpstreamConfig::Proxy {
                protocol: Protocol::Socks5,
                address,
                credentials,
            }
        }
        (false, None, Some(address)) => {
            if args.host_loopback {
                return Err("--host-loopback is only valid with --direct".into());
            }
            UpstreamConfig::Proxy {
                protocol: Protocol::HttpConnect,
                address,
                credentials,
            }
        }
        _ => return Err("select exactly one of --direct, --socks5, or --http-connect".into()),
    };
    let config = LaunchConfig {
        command: args.command,
        name: args.name,
        runtime_root: args.runtime_dir,
        network: NetworkConfig::synthetic(
            !args.no_ipv4,
            !args.no_ipv6,
            args.tap_mtu,
            args.tap_offload == "on",
        ),
        upstream,
        max_tcp_flows: args.max_tcp_flows,
        max_pending_tcp_bytes: args.max_pending_tcp_bytes,
        max_retained_tcp_bytes: args.max_retained_tcp_bytes,
        tcp_receive_buffer_bytes: args.tcp_receive_buffer_bytes,
        tcp_send_buffer_bytes: args.tcp_send_buffer_bytes,
    };
    Ok(Supervisor::run(config)?.code)
}

fn read_credential(path: &std::path::Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(format!("credential is not a regular file: {}", path.display()).into());
    }
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(format!(
            "credential is not owned by the current user: {}",
            path.display()
        )
        .into());
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(format!(
            "credential permissions must not allow group or other access: {}",
            path.display()
        )
        .into());
    }
    let mut value = Vec::with_capacity(256);
    Read::by_ref(&mut file).take(257).read_to_end(&mut value)?;
    if value.ends_with(b"\n") {
        value.pop();
        if value.ends_with(b"\r") {
            value.pop();
        }
    }
    if value.len() > 255 {
        return Err(format!("credential exceeds 255 bytes: {}", path.display()).into());
    }
    Ok(value)
}

fn status(args: StatusArgs) -> Result<i32, Box<dyn std::error::Error>> {
    let root = match args.runtime_dir {
        Some(root) => root,
        None => {
            let xdg = std::env::var_os("XDG_RUNTIME_DIR").ok_or("XDG_RUNTIME_DIR is not set")?;
            PathBuf::from(xdg).join("yayatht")
        }
    };
    let socket = root.join(&args.name).join("control.sock");
    let mut stream = UnixStream::connect(socket)?;
    let request = yayatht_sys::control::encode(yayatht_sys::control::Kind::Status, 1, &[])?;
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let message = yayatht_sys::control::decode(&response)?;
    if message.kind != yayatht_sys::control::Kind::Status {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid status reply").into());
    }
    if args.json {
        println!("{}", String::from_utf8_lossy(message.payload));
    } else {
        let value: serde_json::Value = serde_json::from_slice(message.payload)?;
        println!(
            "{}: {} (target pid {})",
            value["instance_id"].as_str().unwrap_or("unknown"),
            value["state"].as_str().unwrap_or("unknown"),
            value["target_pid"].as_i64().unwrap_or_default()
        );
    }
    Ok(0)
}
