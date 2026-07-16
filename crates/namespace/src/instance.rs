use getrandom::fill as random_fill;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstanceMetadata {
    pub instance_id: String,
    pub nonce: String,
    pub version: String,
    pub started_unix_ms: u128,
    pub supervisor_pid: u32,
    pub dataplane_pid: Option<i32>,
    pub namespace_init_pid: Option<i32>,
    pub target_pid: Option<i32>,
    pub network_namespace_inode: Option<u64>,
    pub state: String,
}

pub struct Instance {
    pub directory: PathBuf,
    pub control_path: PathBuf,
    pub listener: UnixListener,
    metadata_path: PathBuf,
    metadata: InstanceMetadata,
}

impl Instance {
    pub fn create(name: Option<&str>, runtime_root: Option<&Path>) -> io::Result<Self> {
        let root = secure_runtime_root(runtime_root)?;
        let instance_id = name.map_or_else(random_identifier, |value| Ok(value.to_owned()))?;
        let directory = root.join(&instance_id);
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let control_path = directory.join("control.sock");
        let listener = UnixListener::bind(&control_path)?;
        fs::set_permissions(&control_path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let metadata_path = directory.join("instance.json");
        let metadata = InstanceMetadata {
            instance_id,
            nonce: random_identifier()?,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            started_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            supervisor_pid: std::process::id(),
            dataplane_pid: None,
            namespace_init_pid: None,
            target_pid: None,
            network_namespace_inode: None,
            state: "starting".to_owned(),
        };
        let mut instance = Self {
            directory,
            control_path,
            listener,
            metadata_path,
            metadata,
        };
        instance.persist()?;
        Ok(instance)
    }

    #[must_use]
    pub fn metadata(&self) -> &InstanceMetadata {
        &self.metadata
    }

    pub fn update_children(&mut self, dataplane: i32, namespace_init: i32) -> io::Result<()> {
        self.metadata.dataplane_pid = Some(dataplane);
        self.metadata.namespace_init_pid = Some(namespace_init);
        let namespace = fs::metadata(format!("/proc/{namespace_init}/ns/net"))?;
        self.metadata.network_namespace_inode = Some(namespace.ino());
        self.persist()
    }

    pub fn set_target(&mut self, target: i32) -> io::Result<()> {
        self.metadata.target_pid = Some(target);
        self.metadata.state = "running".to_owned();
        self.persist()
    }

    pub fn set_state(&mut self, state: &str) -> io::Result<()> {
        self.metadata.state = state.to_owned();
        self.persist()
    }

    pub fn metadata_json(&self) -> io::Result<Vec<u8>> {
        serde_json::to_vec_pretty(&self.metadata).map_err(io::Error::other)
    }

    /// Writes the namespace-visible `resolv.conf` into the instance
    /// directory and returns its path. World-readable so any uid inside
    /// the namespace can read it through the bind mount.
    pub fn write_resolv_conf(&self, contents: &str) -> io::Result<PathBuf> {
        let path = self.directory.join("resolv.conf");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o644)
            .open(&path)?;
        file.write_all(contents.as_bytes())?;
        Ok(path)
    }

    fn persist(&mut self) -> io::Result<()> {
        let temporary = self.directory.join("instance.json.tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        serde_json::to_writer_pretty(&mut file, &self.metadata).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(temporary, &self.metadata_path)
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let nonce_matches = fs::read(&self.metadata_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<InstanceMetadata>(&bytes).ok())
            .is_some_and(|metadata| metadata.nonce == self.metadata.nonce);
        if !nonce_matches {
            return;
        }
        let _ = fs::remove_file(&self.control_path);
        let _ = fs::remove_file(&self.metadata_path);
        let _ = fs::remove_file(self.directory.join("resolv.conf"));
        let _ = fs::remove_dir(&self.directory);
    }
}

fn secure_runtime_root(override_root: Option<&Path>) -> io::Result<PathBuf> {
    let root = if let Some(root) = override_root {
        root.to_owned()
    } else {
        let xdg = std::env::var_os("XDG_RUNTIME_DIR")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "XDG_RUNTIME_DIR is not set"))?;
        let xdg = PathBuf::from(xdg);
        validate_owned_private_directory(&xdg)?;
        xdg.join("yayatht")
    };
    if !root.exists() {
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
    validate_owned_private_directory(&root)?;
    Ok(root)
}

fn validate_owned_private_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime path is not a real directory",
        ));
    }
    if metadata.uid() != rustix::process::getuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime directory must be owned by the caller and mode 0700",
        ));
    }
    Ok(())
}

fn random_identifier() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    random_fill(&mut bytes)
        .map_err(|error| io::Error::other(format!("getrandom failed: {error:?}")))?;
    let mut out = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(out)
}
