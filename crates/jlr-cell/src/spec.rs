//! Cell specifications and enforcement reports.

use jlr_cbor::{Cbor, Error as CborError, Value, record};
use jlr_model::{AdmissionState, Capability, CellClass, Decision, NetworkMode};
use std::fmt;

/// A kernel control the jail fabric can establish.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Control {
    /// Private user namespace (unprivileged operation).
    UserNs,
    /// Private mount namespace with a rebuilt root.
    MountNs,
    /// Private PID namespace.
    PidNs,
    /// Private IPC namespace.
    IpcNs,
    /// Private UTS namespace.
    UtsNs,
    /// Private network namespace.
    NetNs,
    /// `PR_SET_NO_NEW_PRIVS`.
    NoNewPrivs,
    /// All capabilities dropped, bounding set emptied.
    CapDrop,
    /// seccomp-BPF filter.
    Seccomp,
    /// Landlock filesystem rules.
    LandlockFs,
    /// Landlock TCP port rules.
    LandlockNet,
    /// Per-process resource limits.
    Rlimits,
    /// cgroup v2 memory and process limits.
    Cgroup,
}

impl Control {
    /// Every control, in report order.
    pub const ALL: &'static [Control] = &[
        Control::UserNs,
        Control::MountNs,
        Control::PidNs,
        Control::IpcNs,
        Control::UtsNs,
        Control::NetNs,
        Control::NoNewPrivs,
        Control::CapDrop,
        Control::Seccomp,
        Control::LandlockFs,
        Control::LandlockNet,
        Control::Rlimits,
        Control::Cgroup,
    ];

    /// Stable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Control::UserNs => "user-ns",
            Control::MountNs => "mount-ns",
            Control::PidNs => "pid-ns",
            Control::IpcNs => "ipc-ns",
            Control::UtsNs => "uts-ns",
            Control::NetNs => "net-ns",
            Control::NoNewPrivs => "no-new-privs",
            Control::CapDrop => "cap-drop",
            Control::Seccomp => "seccomp",
            Control::LandlockFs => "landlock-fs",
            Control::LandlockNet => "landlock-net",
            Control::Rlimits => "rlimits",
            Control::Cgroup => "cgroup",
        }
    }

    /// Parses [`Control::as_str`].
    pub fn parse(s: &str) -> Option<Control> {
        Control::ALL.iter().copied().find(|c| c.as_str() == s)
    }
}

impl fmt::Display for Control {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Overall result of establishing a cell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// Every requested control is active.
    Full = 1,
    /// Some optional control is missing; every mandatory control is active.
    Partial = 2,
    /// A mandatory control could not be established; nothing was started.
    Refused = 3,
}

impl Cbor for Status {
    fn to_value(&self) -> Value {
        Value::Uint(*self as u64)
    }
    fn from_value(v: &Value) -> Result<Self, CborError> {
        match v.as_u64()? {
            1 => Ok(Status::Full),
            2 => Ok(Status::Partial),
            3 => Ok(Status::Refused),
            _ => Err(CborError::Invalid("unknown enforcement status")),
        }
    }
}

record! {
    /// What was actually enforced. Missing mandatory controls are never
    /// reported as full enforcement.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EnforcementReport {
        /// Kernel release string.
        1 => kernel: String,
        /// Controls that were requested.
        2 => requested: Vec<String>,
        /// Controls that are active.
        3 => active: Vec<String>,
        /// Requested controls that could not be established, with the reason.
        4 => unavailable: Vec<String>,
        /// Mandatory controls among those unavailable.
        5 => mandatory_missing: Vec<String>,
        /// Overall status.
        6 => status: Status,
        /// Landlock ABI version supported by the kernel, when known.
        7 => landlock_abi: Option<u32>,
        /// Number of syscalls the seccomp filter denies.
        8 => seccomp_denied: u32,
    }
}

impl EnforcementReport {
    /// Whether `control` is active.
    pub fn is_active(&self, control: Control) -> bool {
        self.active.iter().any(|a| a == control.as_str())
    }
}

/// Resource ceilings for a cell.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    /// Memory ceiling in bytes (needs cgroup v2).
    pub memory_bytes: Option<u64>,
    /// Maximum number of processes (needs cgroup v2).
    pub pids_max: Option<u64>,
    /// CPU seconds per process.
    pub cpu_secs: Option<u64>,
    /// Wall-clock seconds before the cell is killed.
    pub wall_secs: Option<u64>,
    /// Maximum open files per process.
    pub nofile: Option<u64>,
}

record! {
    /// A complete description of one cell, passed to the helper.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CellSpec {
        /// Jail class.
        1 => class: CellClass,
        /// Network mode.
        2 => network: NetworkMode,
        /// Capabilities granted.
        3 => capabilities: Vec<Capability>,
        /// Memory ceiling in bytes.
        4 => memory_bytes: Option<u64>,
        /// Process ceiling.
        5 => pids_max: Option<u64>,
        /// CPU seconds per process.
        6 => cpu_secs: Option<u64>,
        /// Wall-clock seconds.
        7 => wall_secs: Option<u64>,
        /// Open-file limit.
        8 => nofile: Option<u64>,
        /// Size of the private `/tmp` in MiB.
        9 => tmp_mib: u64,
        /// Hostname inside the cell.
        10 => hostname: String,
        /// Controls that must be active or the launch is refused.
        11 => mandatory: Vec<String>,
        /// Environment, `KEY=VALUE`.
        12 => env: Vec<String>,
        /// Program name and arguments.
        13 => argv: Vec<String>,
    }
}

/// Reasons a cell cannot be described or started.
#[derive(Debug)]
pub enum CellError {
    /// The decision does not permit execution in a cell.
    NotRunnable(AdmissionState),
    /// The requested cell class or network mode is not implemented.
    Unsupported(String),
    /// Mandatory controls could not be established; nothing was started.
    Refused(Box<EnforcementReport>),
    /// Setup failed for another reason.
    Setup(String),
    /// I/O error.
    Io(std::io::Error),
}

impl fmt::Display for CellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CellError::NotRunnable(s) => write!(f, "state {s} does not permit execution"),
            CellError::Unsupported(s) => write!(f, "unsupported: {s}"),
            CellError::Refused(r) => {
                write!(f, "refused: mandatory controls missing: {}", r.mandatory_missing.join(", "))
            }
            CellError::Setup(s) => write!(f, "cell setup failed: {s}"),
            CellError::Io(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for CellError {}
impl From<std::io::Error> for CellError {
    fn from(e: std::io::Error) -> Self {
        CellError::Io(e)
    }
}

impl CellSpec {
    /// Derives the jail for a decision. Pure and deterministic: the same
    /// decision, argv and environment always yield the same specification.
    pub fn from_decision(d: &Decision, argv: Vec<String>, env: Vec<String>) -> Result<CellSpec, CellError> {
        match d.state {
            AdmissionState::Observed | AdmissionState::Verified | AdmissionState::Admitted => {}
            other => return Err(CellError::NotRunnable(other)),
        }
        if d.state == AdmissionState::Observed && d.cell != CellClass::Cell0 {
            return Err(CellError::Unsupported("observed artifacts run only in CELL-0".into()));
        }
        let (limits, tmp_mib) = match d.cell {
            CellClass::Cell0 => (
                Limits {
                    memory_bytes: Some(512 << 20),
                    pids_max: Some(64),
                    cpu_secs: Some(120),
                    wall_secs: Some(600),
                    nofile: Some(256),
                },
                16,
            ),
            CellClass::Cell1 => (
                Limits {
                    memory_bytes: Some(2 << 30),
                    pids_max: Some(512),
                    cpu_secs: None,
                    wall_secs: None,
                    nofile: Some(1024),
                },
                128,
            ),
            CellClass::Cell2 => (
                Limits { memory_bytes: None, pids_max: None, cpu_secs: None, wall_secs: None, nofile: Some(65536) },
                512,
            ),
            CellClass::Cell3 | CellClass::CellR => {
                return Err(CellError::Unsupported(format!("{} components are not launched through cells", d.cell)));
            }
        };
        if matches!(d.network, NetworkMode::MediatedProxy | NetworkMode::PrivilegedNetwork) {
            return Err(CellError::Unsupported(format!("network mode {} is not implemented", d.network)));
        }
        let mut mandatory =
            vec![Control::MountNs, Control::PidNs, Control::NoNewPrivs, Control::CapDrop, Control::Seccomp];
        if matches!(d.network, NetworkMode::None | NetworkMode::LoopbackOnly) {
            mandatory.push(Control::NetNs);
        }
        if d.network == NetworkMode::DestinationAllowlist {
            mandatory.push(Control::LandlockNet);
        }
        let name = argv.first().cloned().unwrap_or_default();
        Ok(CellSpec {
            class: d.cell,
            network: d.network,
            capabilities: d.capabilities.clone(),
            memory_bytes: limits.memory_bytes,
            pids_max: limits.pids_max,
            cpu_secs: limits.cpu_secs,
            wall_secs: limits.wall_secs,
            nofile: limits.nofile,
            tmp_mib,
            hostname: format!(
                "cell-{}",
                name.rsplit('/')
                    .next()
                    .unwrap_or("x")
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .take(20)
                    .collect::<String>()
            ),
            mandatory: mandatory.iter().map(|c| c.as_str().to_owned()).collect(),
            env,
            argv,
        })
    }

    /// The controls this specification asks for.
    pub fn requested_controls(&self) -> Vec<Control> {
        let mut v = vec![
            Control::MountNs,
            Control::PidNs,
            Control::IpcNs,
            Control::UtsNs,
            Control::NoNewPrivs,
            Control::CapDrop,
            Control::Seccomp,
            Control::LandlockFs,
            Control::Rlimits,
        ];
        if matches!(self.network, NetworkMode::None | NetworkMode::LoopbackOnly) {
            v.push(Control::NetNs);
        }
        if self.network == NetworkMode::DestinationAllowlist {
            v.push(Control::LandlockNet);
        }
        if self.memory_bytes.is_some() || self.pids_max.is_some() {
            v.push(Control::Cgroup);
        }
        v
    }

    /// The mandatory controls parsed back into [`Control`]s.
    pub fn mandatory_controls(&self) -> Vec<Control> {
        self.mandatory.iter().filter_map(|s| Control::parse(s)).collect()
    }
}
