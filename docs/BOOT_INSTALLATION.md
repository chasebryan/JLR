# JLR Boot and Installation Model

## 1. JLR-first installation

The preferred architecture is:

1. install JLR
2. establish its immutable boot and recovery partitions
3. enroll trust anchors
4. install the host Linux distribution into a separate target
5. register host boot artifacts with JLR
6. measure and admit the initial host state
7. boot the host through JLR policy

This makes JLR the persistent governance and recovery layer rather than an application installed after the host.

## 2. Suggested disk layout

A reference layout may use:

~~~text
EFI-SYSTEM       FAT32     firmware boot files
JLR-BOOT         read-only signed loader + manifest
JLR-BASE-A       immutable system image
JLR-BASE-B       immutable fallback system image
JLR-STATE        encrypted trusted mutable state
JLR-EVIDENCE     append-only event/measurement store
JLR-RECOVERY     immutable recovery image
HOST-ROOT        host Linux
HOST-DATA        host/user data
~~~

Actual partitioning is platform-specific.

## 3. A/B base images

JLR should use A/B base slots.

Update sequence:

1. running slot A validates signed update
2. write new immutable image to slot B
3. verify full content digest
4. record pending boot
5. reboot to B
6. perform self-test
7. mark B healthy
8. retain A for rollback until policy expires it

A failed B boot returns to A or recovery.

## 4. Host installation

The host installer should run without permission to overwrite JLR partitions.

Where practical:

- expose only the intended host target
- preserve JLR EFI entries
- verify bootloader changes after host installation
- re-measure host kernel/initramfs
- require explicit admission of changed host boot artifacts

## 5. Boot sequence

~~~text
firmware
  -> JLR loader
  -> verify signed manifest
  -> verify JLR base slot
  -> load JLR RAM environment
  -> verify policy/evidence state
  -> measure host boot set
  -> evaluate host admission
  -> launch host or recovery
~~~

## 6. RAM execution

The JLR base should run primarily from RAM after verified loading.

Benefits:

- minimizes runtime writes to trusted code
- allows deterministic reset on reboot
- makes base replacement atomic
- simplifies recovery comparison

Persistent state is explicitly mounted after base verification.

## 7. Puppy Linux usage

Puppy Linux is considered a **build substrate**, not a trusted brand boundary.

The JLR remaster should:

- remove desktop software not needed for governance/recovery
- remove automatic package mutation from the trusted base
- pin required tool versions
- disable unnecessary network services
- replace ad-hoc startup logic with documented deterministic initialization
- separate JLR code and state from Puppy-specific mechanisms
- maintain a complete software bill of materials

Long term, JLR may replace more of the inherited base as the trusted computing base is reduced.

## 8. Encryption

Sensitive persistent JLR state should support authenticated disk encryption.

Keys may be:

- operator-entered
- hardware-token protected
- TPM sealed
- split between machine and operator factors

Encryption does not replace integrity verification.
