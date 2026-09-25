//! Parent-side launcher.

use crate::init::encode_spec;
use crate::sealed::SealedExe;
use crate::spec::{CellError, CellSpec, EnforcementReport, Status};
use crate::sys;
use jlr_cbor::Cbor;
use nix::unistd::pipe;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// A running cell.
#[derive(Debug)]
pub struct Running {
    child: Child,
    report: EnforcementReport,
}

/// How a cell ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Exit code (128 + signal number when killed by a signal).
    pub code: i32,
    /// Terminating signal, if any.
    pub signal: Option<i32>,
    /// What was enforced.
    pub report: EnforcementReport,
}

/// Standard streams for the workload.
#[derive(Debug)]
pub struct Stdio3 {
    /// Standard input.
    pub stdin: Stdio,
    /// Standard output.
    pub stdout: Stdio,
    /// Standard error.
    pub stderr: Stdio,
}

impl Stdio3 {
    /// Inherit the caller's streams.
    pub fn inherit() -> Self {
        Stdio3 { stdin: Stdio::inherit(), stdout: Stdio::inherit(), stderr: Stdio::inherit() }
    }

    /// Discard input, capture nothing: null on all three.
    pub fn null() -> Self {
        Stdio3 { stdin: Stdio::null(), stdout: Stdio::null(), stderr: Stdio::null() }
    }

    /// Null input and piped output for capture.
    pub fn captured() -> Self {
        Stdio3 { stdin: Stdio::null(), stdout: Stdio::piped(), stderr: Stdio::piped() }
    }
}

/// Starts a cell and returns once its [`EnforcementReport`] is known.
///
/// `helper` is the path of the `jlr-cell-init` binary. When a mandatory
/// control is missing the helper exits without running the workload and this
/// function returns [`CellError::Refused`] carrying the report.
pub fn launch(helper: &Path, exe: &SealedExe, spec: &CellSpec, io: Stdio3) -> Result<Running, CellError> {
    if !exe.is_fully_sealed() {
        return Err(CellError::Setup("executable is not sealed".into()));
    }
    let (read_end, write_end) = pipe().map_err(|e| CellError::Io(e.into()))?;
    let exe_fd = exe.file().as_raw_fd();
    let wr = write_end.as_raw_fd();

    let mut cmd = Command::new(helper);
    cmd.arg("stage1").arg(encode_spec(spec)).env_clear().stdin(io.stdin).stdout(io.stdout).stderr(io.stderr);
    // SAFETY: the closure runs between fork and exec and only calls fcntl, dup2
    // and close, which are async-signal-safe; it allocates nothing.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(move || sys::place_fds(exe_fd, 3, wr, 4));
    }
    let child = cmd.spawn().map_err(CellError::Io)?;
    drop(write_end);

    // The helper writes exactly one length-prefixed report; do not wait for EOF,
    // because the workload keeps the pipe open for as long as it runs.
    let mut r = std::fs::File::from(read_end);
    let mut len = [0u8; 4];
    let mut child = child;
    if r.read_exact(&mut len).is_err() {
        let st = child.wait().map_err(CellError::Io)?;
        return Err(CellError::Setup(format!("cell helper exited ({st}) before reporting")));
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > 1 << 20 {
        return Err(CellError::Setup("implausible report length".into()));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).map_err(CellError::Io)?;
    let report = EnforcementReport::from_cbor(&body).map_err(|e| CellError::Setup(format!("bad report: {e}")))?;
    if report.status == Status::Refused {
        let _ = child.wait();
        return Err(CellError::Refused(Box::new(report)));
    }
    Ok(Running { child, report })
}

impl Running {
    /// The enforcement report established at launch.
    pub fn report(&self) -> &EnforcementReport {
        &self.report
    }

    /// Standard output of the cell when captured.
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }

    /// Standard error of the cell when captured.
    pub fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.stderr.take()
    }

    /// Kills the cell. Killing PID 1 of its namespace ends every process in it.
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.child.kill()
    }

    /// Waits for the cell to end.
    pub fn wait(mut self) -> std::io::Result<Outcome> {
        let st = self.child.wait()?;
        let signal = st.signal();
        let code = st.code().unwrap_or_else(|| 128 + signal.unwrap_or(0));
        Ok(Outcome { code, signal, report: self.report })
    }
}

impl Running {
    /// Waits and returns everything the cell wrote to stdout and stderr.
    pub fn wait_with_output(mut self) -> std::io::Result<(Outcome, Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut so = self.child.stdout.take();
        let mut se = self.child.stderr.take();
        let t = so.take().map(|mut s| {
            std::thread::spawn(move || {
                let mut v = Vec::new();
                let _ = s.read_to_end(&mut v);
                v
            })
        });
        if let Some(mut s) = se.take() {
            let _ = s.read_to_end(&mut err);
        }
        if let Some(t) = t {
            out = t.join().unwrap_or_default();
        }
        let outcome = self.wait()?;
        Ok((outcome, out, err))
    }
}
