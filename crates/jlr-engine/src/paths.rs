//! Layout of the state directory.

use std::path::{Path, PathBuf};

/// Paths inside a JLR state directory.
#[derive(Clone, Debug)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    /// A state directory rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Paths { root: root.into() }
    }

    /// The default state directory: `$JLR_STATE`, else `/var/lib/jlr` for root,
    /// else `$XDG_STATE_HOME/jlr` or `~/.local/state/jlr`.
    pub fn default_location() -> Self {
        if let Some(p) = std::env::var_os("JLR_STATE") {
            return Paths::new(p);
        }
        let is_root =
            std::fs::metadata("/proc/self").map(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0).unwrap_or(false);
        if is_root {
            return Paths::new("/var/lib/jlr");
        }
        if let Some(x) = std::env::var_os("XDG_STATE_HOME") {
            return Paths::new(Path::new(&x).join("jlr"));
        }
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
        Paths::new(home.join(".local/state/jlr"))
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Node identity record.
    pub fn node(&self) -> PathBuf {
        self.root.join("node.cbor")
    }
    /// Private key files.
    pub fn keys(&self) -> PathBuf {
        self.root.join("keys")
    }
    /// The device key.
    pub fn device_key(&self) -> PathBuf {
        self.keys().join("device.jlrkey")
    }
    /// The policy key.
    pub fn policy_key(&self) -> PathBuf {
        self.keys().join("policy.jlrkey")
    }
    /// Trust anchors.
    pub fn anchors(&self) -> PathBuf {
        self.root.join("trust/anchors.cbor")
    }
    /// Active signed policy.
    pub fn policy(&self) -> PathBuf {
        self.root.join("policy/active.cose")
    }
    /// Active signed revocations.
    pub fn revocations(&self) -> PathBuf {
        self.root.join("policy/revocations.cose")
    }
    /// Directory of signed approvals.
    pub fn approvals(&self) -> PathBuf {
        self.root.join("approvals")
    }
    /// Directory of signed baselines.
    pub fn baselines(&self) -> PathBuf {
        self.root.join("baselines")
    }
    /// The evidence ledger.
    pub fn ledger(&self) -> PathBuf {
        self.root.join("ledger")
    }
    /// Content-addressed object store.
    pub fn objects(&self) -> PathBuf {
        self.root.join("objects")
    }
    /// Disposable derived data; safe to delete at any time.
    pub fn cache(&self) -> PathBuf {
        self.root.join("cache")
    }
    /// The path index (a cache).
    pub fn index(&self) -> PathBuf {
        self.root.join("index.cbor")
    }
}
