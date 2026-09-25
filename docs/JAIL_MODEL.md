# JLR Jail Model

## 1. Goal

A JLR jail is a policy-defined execution cell that limits what a process can observe, modify, communicate with, and consume.

The jail is a composition of kernel mechanisms.

## 2. Jail classes

### CELL-0 — Analysis only

For untrusted binaries.

- isolated user/PID/mount/network namespaces
- read-only artifact input
- disposable tmpfs
- no host home
- no host network by default
- no device access
- no privilege elevation
- strict resource ceilings

### CELL-1 — Restricted application

For verified applications not yet broadly admitted.

- scoped persistent storage
- optional mediated network
- no host administration
- no kernel access
- no arbitrary device access

### CELL-2 — Admitted desktop/service workload

For software with explicit capabilities.

- user data access per policy
- network per policy
- selected device access
- cgroup controls
- seccomp profile

### CELL-3 — Privileged host component

For components that genuinely require elevated host integration.

Requires stronger provenance and explicit policy.

### CELL-R — Recovery tooling

Exists only in recovery context.

May receive temporary elevated storage capabilities but must be explicitly invoked and logged.

## 3. Capability vocabulary

JLR policy should use semantic capabilities rather than raw UID assumptions.

Examples:

- FS_READ:/home/user/Documents
- FS_WRITE:/var/lib/app
- NET_CONNECT:example.org:443
- NET_LISTEN:127.0.0.1:8080
- DEV_AUDIO
- DEV_GPU
- DEV_USB:<class>
- PROC_SPAWN:<jpn>
- IPC_DBUS:<name>
- HOST_SERVICE_CONTROL:<service>
- KERNEL_MODULE_LOAD
- RAW_NETWORK
- RAW_BLOCK_WRITE

The last three are high-risk capabilities.

## 4. Filesystem

Rules:

- host root should be read-only or hidden unless explicitly needed
- executable inputs should be mounted read-only where possible
- writable and executable mappings should be minimized
- persistent writes should be scoped
- temporary files should default to per-cell tmpfs
- secrets should be injected only when required

## 5. Networking

Each jail has one of:

- NONE
- LOOPBACK_ONLY
- DESTINATION_ALLOWLIST
- MEDIATED_PROXY
- FULL_USER_NETWORK
- PRIVILEGED_NETWORK

Network policy is part of the JPN admission record.

## 6. Process boundary

A jailed process must not be able to:

- ptrace arbitrary host processes
- join host namespaces
- modify host cgroups
- change its own JLR policy
- access JLR private keys
- directly edit trusted manifests

## 7. Kernel boundary

Containers are not a defense against a hostile kernel.

If the host kernel is untrusted, JLR must not assume namespace confinement is sound. High-risk analysis should be moved to a stronger boundary such as a VM or separate machine when feasible.

## 8. Escape response

A suspected escape or sandbox bypass triggers:

1. terminate affected workload where safe
2. mark workload DEGRADED or HOSTILE
3. snapshot relevant evidence
4. isolate related child processes
5. require operator review
6. consider host trust degraded if kernel-level bypass is plausible
