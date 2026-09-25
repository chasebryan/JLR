//! Boot media: which device to trust, and how boot state is read from and written to it.
//!
//! Everything here is plain file and byte handling so it can be tested without a virtual machine.

use crate::manifest::BootError;
use crate::state::BootState;
use jlr_cbor::Cbor;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

/// How much of a device must be read to identify its file system.
pub const HEAD_LEN: usize = 2048;

/// Reads the file system identifier out of the first [`HEAD_LEN`] bytes of a device, without mounting it.
///
/// * ext2/3/4: the 128-bit UUID, as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
/// * FAT: the 32-bit volume serial, as `xxxx-xxxx`.
///
/// The result is lower case. A file system with no identifier (iso9660, an unformatted device) returns `None`.
/// Identifying a device before mounting means an initramfs pinned to one medium never lets the kernel parse
/// the file system of any other disk.
pub fn filesystem_id(head: &[u8]) -> Option<String> {
    // ext superblock: 1024 bytes in; magic 0xEF53 at +56, UUID at +104.
    if head.len() >= 1024 + 120 && head[1024 + 56..1024 + 58] == [0x53, 0xEF] {
        let u = &head[1024 + 104..1024 + 120];
        let h: String = u.iter().map(|b| format!("{b:02x}")).collect();
        return Some(format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]));
    }
    // FAT boot sector.
    if head.len() >= 512 && head[510] == 0x55 && head[511] == 0xAA {
        let serial = if &head[82..90] == b"FAT32   " {
            Some(&head[67..71])
        } else if &head[54..57] == b"FAT" {
            Some(&head[39..43])
        } else {
            None
        }?;
        return Some(format!("{:02x}{:02x}-{:02x}{:02x}", serial[3], serial[2], serial[1], serial[0]));
    }
    None
}

/// Parses a media pin: `uuid=<id>`, `id=<id>` or the bare identifier. The result is lower case.
pub fn parse_pin(text: &str) -> Option<String> {
    let t = text.trim();
    let t = t.strip_prefix("uuid=").or_else(|| t.strip_prefix("id=")).unwrap_or(t).trim();
    let ok = !t.is_empty() && t.len() <= 64 && t.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    ok.then(|| t.to_ascii_lowercase())
}

const STATE_FILE: &str = "bootstate.cbor";

/// What reading the state of a medium found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateRead {
    /// No state has ever been written: a freshly provisioned medium.
    Fresh(BootState),
    /// The state file, as written.
    Loaded(BootState),
    /// The state file was missing but an interrupted write left a complete new one, which was used.
    Recovered(BootState),
}

impl StateRead {
    /// The state, whichever way it was obtained.
    pub fn into_state(self) -> BootState {
        match self {
            StateRead::Fresh(s) | StateRead::Loaded(s) | StateRead::Recovered(s) => s,
        }
    }
}

/// Reads the boot state under `<media>/jlr`.
///
/// Only "the file does not exist" means a fresh medium. Every other failure (an I/O error, a damaged file,
/// a directory in its place) is an error, because treating it as fresh would reset the rollback floor to
/// zero and let an older release boot. A missing file with a complete `.new` beside it is what a power cut
/// during a rename on a FAT volume leaves behind, and the `.new` is used.
pub fn read_state(media: &Path) -> Result<StateRead, BootError> {
    let path = media.join("jlr").join(STATE_FILE);
    let parse = |b: &[u8]| BootState::from_cbor(b).map_err(|e| BootError::Io(format!("boot state is damaged: {e}")));
    match fs::read(&path) {
        Ok(b) => parse(&b).map(StateRead::Loaded),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let pending = media.join("jlr").join(format!("{STATE_FILE}.new"));
            match fs::read(&pending) {
                Ok(b) => parse(&b).map(StateRead::Recovered),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(StateRead::Fresh(BootState::fresh())),
                Err(e) => Err(BootError::Io(format!("{}: {e}", pending.display()))),
            }
        }
        Err(e) => Err(BootError::Io(format!("{}: {e}", path.display()))),
    }
}

/// Writes the boot state durably: the new file is synced before it replaces the old one, and the directory is
/// synced afterwards.
pub fn write_state(media: &Path, state: &BootState) -> io::Result<()> {
    let dir = media.join("jlr");
    let path = dir.join(STATE_FILE);
    let tmp = dir.join(format!("{STATE_FILE}.new"));
    let mut f = File::create(&tmp)?;
    f.write_all(&state.to_cbor())?;
    f.sync_all()?;
    fs::rename(&tmp, &path)?;
    File::open(&dir).and_then(|d| d.sync_all())
}
