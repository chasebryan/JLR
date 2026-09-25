//! Semantic capabilities, jail classes and network modes.

use crate::artifact::coded_enum;
use jlr_cbor::{Cbor, Error, Value};
use std::fmt;

coded_enum! {
    /// Jail class of an execution cell (least to most authority, recovery last).
    pub enum CellClass: u8 {
        /// Analysis only: no host home, no network, no devices, tmpfs scratch.
        Cell0 = 0 => "CELL-0",
        /// Restricted application with scoped persistent storage.
        Cell1 = 1 => "CELL-1",
        /// Admitted desktop or service workload.
        Cell2 = 2 => "CELL-2",
        /// Privileged host component.
        Cell3 = 3 => "CELL-3",
        /// Recovery tooling, valid only in the recovery context.
        CellR = 4 => "CELL-R",
    }
}

coded_enum! {
    /// Network policy attached to a cell.
    pub enum NetworkMode: u8 {
        /// No network at all.
        None = 0 => "NONE",
        /// Loopback inside the cell only.
        LoopbackOnly = 1 => "LOOPBACK_ONLY",
        /// Only the destinations named by capabilities.
        DestinationAllowlist = 2 => "DESTINATION_ALLOWLIST",
        /// Traffic goes through a mediating proxy.
        MediatedProxy = 3 => "MEDIATED_PROXY",
        /// The user's ordinary network.
        FullUserNetwork = 4 => "FULL_USER_NETWORK",
        /// Raw or privileged network access.
        PrivilegedNetwork = 5 => "PRIVILEGED_NETWORK",
    }
}

/// A malformed capability string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityError(pub String);

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid capability: {}", self.0)
    }
}
impl std::error::Error for CapabilityError {}

/// A specific permission. Absence of a capability means denial.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Capability {
    /// Read below an absolute path.
    FsRead(String),
    /// Write below an absolute path.
    FsWrite(String),
    /// Connect to `host:port`.
    NetConnect(String, u16),
    /// Listen on `addr:port`.
    NetListen(String, u16),
    /// Audio devices.
    DevAudio,
    /// GPU render nodes.
    DevGpu,
    /// A USB device class.
    DevUsb(String),
    /// Spawn a named EPN.
    ProcSpawn(String),
    /// Talk to a D-Bus name.
    IpcDbus(String),
    /// Control a host service.
    HostServiceControl(String),
    /// Load kernel modules. High risk.
    KernelModuleLoad,
    /// Raw sockets. High risk.
    RawNetwork,
    /// Write raw block devices. High risk.
    RawBlockWrite,
}

fn validate_path(p: &str) -> Result<String, CapabilityError> {
    if !p.starts_with('/') || p.contains('\0') {
        return Err(CapabilityError(format!("path must be absolute: {p:?}")));
    }
    if p.split('/').any(|c| c == "." || c == "..") {
        return Err(CapabilityError(format!("path must be normalized: {p:?}")));
    }
    if p.contains("//") || (p.len() > 1 && p.ends_with('/')) {
        return Err(CapabilityError(format!("path must be canonical: {p:?}")));
    }
    Ok(p.to_owned())
}

fn validate_token(kind: &str, s: &str) -> Result<String, CapabilityError> {
    if s.is_empty() || s.len() > 253 || !s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:*@".contains(c)) {
        return Err(CapabilityError(format!("bad {kind}: {s:?}")));
    }
    Ok(s.to_owned())
}

fn split_hostport(what: &str, s: &str) -> Result<(String, u16), CapabilityError> {
    let (host, port) = s.rsplit_once(':').ok_or_else(|| CapabilityError(format!("{what} needs host:port")))?;
    let port: u16 = port.parse().map_err(|_| CapabilityError(format!("bad port in {what}")))?;
    Ok((validate_token("host", host)?, port))
}

impl Capability {
    /// Parses the textual form, for example `FS_READ:/home/u/Documents`.
    pub fn parse(s: &str) -> Result<Capability, CapabilityError> {
        let (name, arg) = match s.split_once(':') {
            Some((n, a)) => (n, Some(a)),
            None => (s, None),
        };
        fn need<'a>(name: &str, a: Option<&'a str>) -> Result<&'a str, CapabilityError> {
            a.ok_or_else(|| CapabilityError(format!("{name} needs an argument")))
        }
        fn none(name: &str, a: Option<&str>) -> Result<(), CapabilityError> {
            match a {
                None => Ok(()),
                Some(_) => Err(CapabilityError(format!("{name} takes no argument"))),
            }
        }
        Ok(match name {
            "FS_READ" => Capability::FsRead(validate_path(need(name, arg)?)?),
            "FS_WRITE" => Capability::FsWrite(validate_path(need(name, arg)?)?),
            "NET_CONNECT" => {
                let (h, p) = split_hostport(name, need(name, arg)?)?;
                Capability::NetConnect(h, p)
            }
            "NET_LISTEN" => {
                let (h, p) = split_hostport(name, need(name, arg)?)?;
                Capability::NetListen(h, p)
            }
            "DEV_AUDIO" => {
                none(name, arg)?;
                Capability::DevAudio
            }
            "DEV_GPU" => {
                none(name, arg)?;
                Capability::DevGpu
            }
            "DEV_USB" => Capability::DevUsb(validate_token("usb class", need(name, arg)?)?),
            "PROC_SPAWN" => Capability::ProcSpawn(validate_token("epn", need(name, arg)?)?),
            "IPC_DBUS" => Capability::IpcDbus(validate_token("bus name", need(name, arg)?)?),
            "HOST_SERVICE_CONTROL" => Capability::HostServiceControl(validate_token("service", need(name, arg)?)?),
            "KERNEL_MODULE_LOAD" => {
                none(name, arg)?;
                Capability::KernelModuleLoad
            }
            "RAW_NETWORK" => {
                none(name, arg)?;
                Capability::RawNetwork
            }
            "RAW_BLOCK_WRITE" => {
                none(name, arg)?;
                Capability::RawBlockWrite
            }
            other => return Err(CapabilityError(format!("unknown capability {other}"))),
        })
    }

    /// Capabilities that always require an explicit human decision.
    pub fn is_high_risk(&self) -> bool {
        matches!(
            self,
            Capability::KernelModuleLoad
                | Capability::RawNetwork
                | Capability::RawBlockWrite
                | Capability::HostServiceControl(_)
                | Capability::DevUsb(_)
        )
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Capability::FsRead(p) => write!(f, "FS_READ:{p}"),
            Capability::FsWrite(p) => write!(f, "FS_WRITE:{p}"),
            Capability::NetConnect(h, p) => write!(f, "NET_CONNECT:{h}:{p}"),
            Capability::NetListen(h, p) => write!(f, "NET_LISTEN:{h}:{p}"),
            Capability::DevAudio => write!(f, "DEV_AUDIO"),
            Capability::DevGpu => write!(f, "DEV_GPU"),
            Capability::DevUsb(c) => write!(f, "DEV_USB:{c}"),
            Capability::ProcSpawn(e) => write!(f, "PROC_SPAWN:{e}"),
            Capability::IpcDbus(n) => write!(f, "IPC_DBUS:{n}"),
            Capability::HostServiceControl(s) => write!(f, "HOST_SERVICE_CONTROL:{s}"),
            Capability::KernelModuleLoad => write!(f, "KERNEL_MODULE_LOAD"),
            Capability::RawNetwork => write!(f, "RAW_NETWORK"),
            Capability::RawBlockWrite => write!(f, "RAW_BLOCK_WRITE"),
        }
    }
}

impl Cbor for Capability {
    fn to_value(&self) -> Value {
        Value::Text(self.to_string())
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        let parsed = Capability::parse(v.as_text()?).map_err(|_| Error::Invalid("capability"))?;
        Ok(parsed)
    }
}
