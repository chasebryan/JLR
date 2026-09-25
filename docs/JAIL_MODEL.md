# JLR Jail Model

## 1. Goal

A **cell** is an execution environment assembled from Linux mechanisms that limits what a process can see, change,
reach and consume. It is not a container technology; it is a composition, and it is a **function of the trust decision**:
`CellSpec::from_decision` is pure, so the same decision always yields the same jail (Phase 4's "reproducible from the EPN
record" exit criterion).

Every launch produces an **enforcement report** stating which controls were requested, which are active, and which could
not be established. A control that is *mandatory* for the cell and missing **refuses the launch**; nothing is started and
nothing is silently downgraded (I-21).

## 2. Cell classes

| Class | Purpose | Implemented | Limits (memory, processes, CPU s, wall s, open files, `/tmp`) |
|---|---|---|---|
| **CELL-0** | Analysis: unknown software | Yes | 512 MiB, 64, 120, 600, 256, 16 MiB |
| **CELL-1** | Verified software not yet broadly admitted | Yes | 2 GiB, 512, none, none, 1024, 128 MiB |
| **CELL-2** | Admitted desktop or service workload | Yes | none, none, none, none, 65536, 512 MiB |
| **CELL-3** | Privileged host component | No: `jlr run` refuses. Host components are governed by the gate and boot chain, not run in cells | n/a |
| **CELL-R** | Recovery tooling | No: recovery context only | n/a |

Memory and process ceilings need cgroup v2; when the session has no delegated cgroup they are reported as unavailable
and `RLIMIT_CPU`, `RLIMIT_NOFILE` and a wall-clock timer still apply.

## 3. Network modes

| Mode | Implementation | Notes |
|---|---|---|
| `NONE` | New network namespace | Not even loopback is up. Mandatory `net-ns` |
| `LOOPBACK_ONLY` | New network namespace with `lo` up | Cannot reach the host's loopback. Mandatory `net-ns` |
| `DESTINATION_ALLOWLIST` | Host network namespace plus Landlock TCP rules | Landlock matches **ports**, not addresses. A `NET_CONNECT:host:port` grants that **port**; the host part is not enforced at IP level. Mandatory `landlock-net` (kernel ABI 4 or later) |
| `FULL_USER_NETWORK` | Host network namespace | No network confinement |
| `MEDIATED_PROXY`, `PRIVILEGED_NETWORK` | Not implemented | The launch is refused, not approximated |

## 4. Controls

| Control | What it does | Mandatory | Established by |
|---|---|:---:|---|
| `user-ns` | Runs the launcher unprivileged; the workload is "root" mapped to the invoking user | when unprivileged | `unshare(CLONE_NEWUSER)`, uid/gid map |
| `mount-ns` | A private root assembled from read-only bind mounts, then `pivot_root` | yes | Stage 2 |
| `pid-ns` | The workload is PID 1 of its own PID namespace | yes | Stage 1 `unshare`, stage 2 is the child |
| `ipc-ns`, `uts-ns` | Private IPC and hostname | no | Stage 1 |
| `net-ns` | See section 3 | when the mode is `NONE` or `LOOPBACK_ONLY` | Stage 1 |
| `no-new-privs` | `PR_SET_NO_NEW_PRIVS`; setuid binaries cannot elevate | yes | Stage 2 |
| `cap-drop` | Bounding set emptied, all sets cleared, then **verified** (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SETUID` must be gone) | yes | Stage 2 |
| `seccomp` | Deny-list filter, 50 syscalls, see section 6 | yes | Stage 2 |
| `landlock-fs` | Write confinement to granted paths, see section 5 | no | Stage 2 |
| `landlock-net` | TCP port rules | when the mode is `DESTINATION_ALLOWLIST` | Stage 2 |
| `rlimits` | `RLIMIT_CORE=0`, `NOFILE`, `CPU` | no | Stage 2 |
| `cgroup` | `memory.max`, `memory.swap.max=0`, `pids.max` in a fresh cgroup | no | Stage 2, before the root is replaced |

`jlr doctor` runs a live cell and prints each of these as `active`, `UNAVAILABLE (reason)` or `not requested`.

## 5. The private root

Built in a mount namespace on a tmpfs, then `pivot_root`ed into, with the old root unmounted and the new root
remounted read-only:

| Path | Contents |
|---|---|
| `/usr`, and `/bin /sbin /lib /lib32 /lib64 /libx32` | Read-only, `nosuid`, `nodev` bind of the host's (symlinks recreated on merged-usr systems). Non-recursive, so submounts do not leak in writable |
| `/etc` | Only `ld.so.cache`, `ld.so.conf(.d)`, `passwd`, `group`, `nsswitch.conf`, `localtime`, `alternatives`; plus `resolv.conf`, `hosts`, `ssl`, `ca-certificates` when the network mode has a network |
| `/dev` | A tmpfs with `null zero full random urandom`, `/dev/shm`, and `fd stdin stdout stderr` links. No terminals, no block devices, no GPU |
| `/proc` | A new procfs for the new PID namespace |
| `/tmp`, `/run` | Private tmpfs, `noexec`, size limited |
| Granted paths | `FS_READ:/p` as a read-only bind at `/p`; `FS_WRITE:/p` as a read-write bind. Nothing else of the host is present |

Absent: `/home`, `/root`, `/var`, `/sys`, the state directory and every key. **What a cell can see is decided by the
mount namespace.** Landlock is scoped to what it can express cleanly: it confines *writes* to the granted paths and
handles TCP ports. Landlock rules are recursive, so allowing a directory listing of `/` would allow everything beneath it;
reads are therefore left to the mount namespace. `EXECUTE` is deliberately not handled, because a sealed memfd has no
place in the file hierarchy for a path rule to name; executability is controlled by read-only, `noexec` mounts.

## 6. seccomp

A **deny list**, installed after capabilities are dropped, with `EPERM` for the 49 denied syscalls and `ENOSYS` for
`clone3` (so libc falls back to `clone`, whose flags a filter can inspect). It removes what gives a process authority over
the kernel, other processes, the namespace layout or the clock and leaves ordinary application behaviour alone:

- process inspection and injection: `ptrace`, `process_vm_readv/writev`, `kcmp`, `pidfd_getfd`;
- the mount API and namespaces: `mount`, `umount2`, `pivot_root`, `chroot`, `setns`, `unshare`, `move_mount`, `open_tree`,
  `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`, and `clone` carrying any `CLONE_NEW*` flag;
- kernel state: `init_module`, `finit_module`, `delete_module`, `kexec_load`, `kexec_file_load`, `reboot`, `swapon`, `swapoff`,
  `acct`, `quotactl`, `lookup_dcookie`;
- the attack surface that is hard to bound: `bpf`, `perf_event_open`, `userfaultfd`, the `keyctl` family, `io_uring_*`,
  `open_by_handle_at`, `name_to_handle_at`;
- the clock and machine identity: `settimeofday`, `clock_settime`, `clock_adjtime`, `adjtimex`, `sethostname`,
  `setdomainname`, `iopl`, `ioperm`.

A deny list is less strict than an allow list and misses syscalls added after it was written. It is used first because an
allow list needs to know what real workloads require, and the observation cells are what will tell it. A CELL-0 allow-list
profile derived from recorded behaviour is the designed replacement.

## 7. Executing the measured bytes

1. The file is opened without following a final symlink and hashed **through that descriptor**.
2. The launcher copies the descriptor's content into a `memfd`, hashing again while it copies, and refuses to continue
   unless the second hash equals the first (a file edited in place between the two is caught).
3. The memfd is **sealed** (no write, grow, shrink or further sealing).
4. Stage 2 `exec`s `/proc/self/fd/3`, the sealed memfd. Path replacement and in-place edits after this point change nothing
   about what runs.

Scripts work: the interpreter is opened through the still-open descriptor. Because `no_new_privs` is set, a script or
binary cannot gain privileges through the exec.

## 8. Rootful and unprivileged launches

| | Unprivileged (`euid != 0`) | Rootful (`euid == 0`) |
|---|---|---|
| Namespaces | User, mount, PID, IPC, UTS, and net when needed | Mount, PID, IPC, UTS, and net when needed |
| Workload identity | "root" mapped to the invoking user; no capabilities | **`nobody` (65534)** after the bounding set is dropped; the process is made dumpable again so `/proc/self` stays reachable |
| Why | A user cannot create other privileges | Real root's file permissions must not apply to anything the workload can reach |

Order matters and is tested in the guest: the bounding set is emptied while `CAP_SETPCAP` is still held, then the uid
changes, then the remaining sets are cleared and verified.

## 9. Two stages, and why

`jlr-cell-init` is re-executed for every cell. **Stage 1** is a fresh single-threaded process, which is what makes
`unshare(CLONE_NEWUSER)` legal and avoids the allocator-after-fork hazards of a multithreaded parent. It creates the
namespaces and starts stage 2; because it `unshare`d the PID namespace first, its child is PID 1 of the new namespace and
can mount a `/proc` that matches. **Stage 2** builds the root, applies every control, writes the report to the parent over
a pipe **before** `exec`, and exits with status 126 without running anything if a mandatory control is missing. Stage 1
enforces the wall-clock limit and kills the namespace by killing PID 1; both stages die if the launcher dies
(`PR_SET_PDEATHSIG`).

Inherited descriptors are fixed: 3 is the sealed executable, 4 is the report pipe.

## 10. What a workload cannot do

Tested with real cells, and mutation-checked so that removing a control makes a test fail:

- see any host path outside its granted binds, including a secret placed in the invoking user's home;
- write anywhere but `/tmp`, `/dev/shm`, `/run` and granted paths; a write inside the cell never reaches the host;
- reach the network in a `NONE` cell, including a listener on the host's loopback;
- create namespaces or `chroot` (`EPERM`), or gain capabilities (`CapEff`, `CapPrm`, `CapBnd`, `CapAmb` are all zero;
  `NoNewPrivs` is 1);
- see host processes (it is PID 1 and `/proc` lists a handful);
- inherit the caller's environment (only the variables in the spec);
- run a different program than the one that was measured, even if the path is replaced and the original file edited.

## 11. Escape response

**Designed.** A suspected escape or bypass should terminate the workload where safe, mark it `DEGRADED` or `REVOKED`,
snapshot the evidence, isolate related children, require operator review, and consider the host's trust degraded if a
kernel-level bypass is plausible. **Today** the launcher records the report and the exit, and a cell that violates
`no_new_privs` or its seccomp filter simply gets `EPERM`. There is no telemetry loop yet that turns a denied syscall into a
state change.

## 12. Known gaps

Stated because they matter:

1. **Cells share the host kernel.** A kernel exploit reachable through the allowed syscalls defeats every control here.
   For hostile code, a VM is the stronger boundary and is designed as a future cell backend.
2. The seccomp filter is a deny list.
3. `NET_CONNECT` host names are not enforced; ports are.
4. No display, audio or input is forwarded, so graphical applications cannot run in a cell yet. The designed answer is a
   Wayland-only socket and portal-style prompts, so that a user's ordinary action grants the capability.
5. cgroup limits need a delegated cgroup.
6. A workload in `FULL_USER_NETWORK` shares the host network namespace and can reach local services.
7. Abstract-namespace Unix sockets are per network namespace, so they are isolated only when the cell has its own.
