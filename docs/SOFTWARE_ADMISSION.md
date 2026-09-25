# JLR Software Admission Lifecycle

## 1. Default rule

New software is not automatically trusted merely because it was downloaded, installed by a package manager, or launched by an administrator.

The default lifecycle is:

~~~text
discover -> identify -> quarantine -> verify -> observe -> admit
~~~

Policy may skip observation for strongly authenticated artifacts with low-risk capability requests, but the skipped step must be explainable from policy.

## 2. Discovery

JLR creates an observation when it detects:

- a new executable
- a modified executable
- a new privileged script
- a new service definition
- a new kernel module
- an installer
- an executable memory image without a known file identity
- a new package transaction

The artifact is assigned or matched to an EPN.

## 3. Static verification

Checks may include:

- cryptographic hashes
- signature validity
- package metadata
- publisher identity
- dependency closure
- interpreter identity
- requested Linux capabilities
- setuid/setgid bits
- writable executable paths
- suspicious ELF metadata
- embedded privileged operations

Static analysis is evidence, not proof of benign behavior.

## 4. Initial capability profile

The Admission Controller creates the smallest execution profile that can support inspection.

Typical defaults:

- no raw devices
- no kernel module loading
- no ptrace outside jail
- no host process visibility
- no arbitrary mount
- no host configuration write
- no unrestricted network
- no privileged ports
- no persistent write outside assigned storage
- cgroup CPU/memory/process limits
- seccomp deny list or allow list

## 5. Observation

Observation cells record security-relevant behavior:

- files opened
- files created
- executable children
- network destinations
- listening sockets
- privilege requests
- namespace operations
- device access
- process injection attempts
- policy denials
- code identity changes

The system should record normalized behavior rather than raw high-volume telemetry forever.

## 6. User verification

When policy requires manual approval, the user sees:

- identity
- source
- signer
- version
- requested privileges
- observed behavior
- unresolved evidence
- exact capability grant being requested

The user can:

- deny
- allow once
- admit under current sandbox
- admit with selected capabilities
- permanently revoke

Approval does not convert weak provenance into strong provenance.

## 7. Admission

An ADMITTED state always has a scope.

Examples:

- may execute as user
- may access a specific directory
- may reach specific network destinations
- may use audio device
- may start a named helper
- may bind a specific port

"Admitted" never means "unrestricted."

## 8. Re-evaluation triggers

Automatic re-evaluation occurs when:

- content hash changes
- dependency changes
- signer is revoked
- policy changes
- host trust changes
- executable path becomes writable by a less-trusted actor
- kernel or sandbox mechanism changes
- new forbidden behavior is observed

## 9. Emergency execution

Recovery scenarios sometimes require unknown tools.

JLR may support EMERGENCY OVERRIDE with:

- explicit operator confirmation
- forced isolation
- no trust promotion
- prominent logging
- automatic expiration
