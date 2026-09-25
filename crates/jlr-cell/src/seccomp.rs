//! seccomp-BPF filters for cells.
//!
//! The filter is a deny list: it removes the syscalls that give a process
//! authority over the kernel, other processes, the namespace layout or the
//! clock, and leaves ordinary application behaviour intact. A stricter
//! allow-list profile for CELL-0 can replace it once observation cells have
//! recorded what real workloads need.

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule, TargetArch,
};
use std::collections::BTreeMap;

/// Syscalls answered with `EPERM`.
const DENY_EPERM: &[i64] = &[
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_kcmp,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_setns,
    libc::SYS_unshare,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_acct,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
    libc::SYS_adjtimex,
    libc::SYS_iopl,
    libc::SYS_ioperm,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    libc::SYS_quotactl,
    libc::SYS_lookup_dcookie,
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_pidfd_getfd,
];

/// Syscalls answered with `ENOSYS` so that libc falls back to the older call
/// whose flags a filter can inspect (`clone3` hides its flags in a struct).
const DENY_ENOSYS: &[i64] = &[libc::SYS_clone3];

/// Everything needed to install the filters.
pub struct Filters {
    /// Programs to install, each with its own default action.
    pub programs: Vec<BpfProgram>,
    /// Number of distinct syscalls the filters deny.
    pub denied: u32,
}

fn arch() -> Result<TargetArch, String> {
    std::env::consts::ARCH.try_into().map_err(|e| format!("unsupported architecture for seccomp: {e}"))
}

fn build(rules: BTreeMap<i64, Vec<SeccompRule>>, action: SeccompAction) -> Result<BpfProgram, String> {
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, action, arch()?).map_err(|e| e.to_string())?;
    filter.try_into().map_err(|e: seccompiler::BackendError| e.to_string())
}

/// Builds the cell filters.
pub fn cell_filters() -> Result<Filters, String> {
    let eperm: BTreeMap<i64, Vec<SeccompRule>> = DENY_EPERM.iter().map(|s| (*s, vec![])).collect();
    let mut eperm = eperm;
    // clone(2) carrying any namespace flag is refused. The flags are the first argument and
    // MaskedEq matches a whole masked value, so there is one rule per flag.
    let mut clone_rules = Vec::new();
    for flag in [
        libc::CLONE_NEWNS,
        libc::CLONE_NEWCGROUP,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWNET,
    ] {
        let f = flag as u64;
        clone_rules.push(
            SeccompRule::new(vec![
                SeccompCondition::new(0, SeccompCmpArgLen::Qword, SeccompCmpOp::MaskedEq(f), f)
                    .map_err(|e| e.to_string())?,
            ])
            .map_err(|e| e.to_string())?,
        );
    }
    eperm.insert(libc::SYS_clone, clone_rules);
    let denied = eperm.len() as u32 + DENY_ENOSYS.len() as u32;

    let enosys: BTreeMap<i64, Vec<SeccompRule>> = DENY_ENOSYS.iter().map(|s| (*s, vec![])).collect();
    Ok(Filters {
        programs: vec![
            build(eperm, SeccompAction::Errno(libc::EPERM as u32))?,
            build(enosys, SeccompAction::Errno(libc::ENOSYS as u32))?,
        ],
        denied,
    })
}

/// Installs the filters on the calling process.
pub fn install(filters: &Filters) -> Result<(), String> {
    for p in &filters.programs {
        seccompiler::apply_filter(p).map_err(|e| e.to_string())?;
    }
    Ok(())
}
