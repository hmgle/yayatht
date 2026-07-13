use clap::{Args, Parser, Subcommand};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use yayatht_namespace::{LaunchConfig, NetworkConfig, Supervisor};

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
struct RunArgs {
    #[arg(long, required = true, help = "Enable the Phase 0 direct TCP backend")]
    direct: bool,
    #[arg(long)]
    name: Option<String>,
    #[arg(long, value_name = "ROOT")]
    runtime_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 4096)]
    max_tcp_flows: usize,
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
    if !args.direct {
        return Err("Phase 0 requires --direct".into());
    }
    let config = LaunchConfig {
        command: args.command,
        name: args.name,
        runtime_root: args.runtime_dir,
        network: NetworkConfig::synthetic(!args.no_ipv4, !args.no_ipv6),
        host_loopback: args.host_loopback,
        max_tcp_flows: args.max_tcp_flows,
    };
    Ok(Supervisor::run(config)?.code)
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
