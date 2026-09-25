//! Artifact classification from file contents and names.

use jlr_model::ArtifactClass;
use std::path::Path;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

fn elf_type(head: &[u8]) -> Option<u16> {
    if head.len() < 18 || &head[..4] != ELF_MAGIC {
        return None;
    }
    // e_ident[EI_DATA]: 1 little endian, 2 big endian.
    match head[5] {
        1 => Some(u16::from_le_bytes([head[16], head[17]])),
        2 => Some(u16::from_be_bytes([head[16], head[17]])),
        _ => None,
    }
}

fn name_of(path: &Path) -> &str {
    path.file_name().and_then(|n| n.to_str()).unwrap_or("")
}

/// Classifies a file by magic bytes, permissions and name.
///
/// Classification is a hint that selects policy tiers, not a security
/// decision: an attacker controls both bytes and names, so unknown content
/// is never classified into a *less* restricted class than [`ArtifactClass::Other`]
/// merely because of its name.
pub fn classify(head: &[u8], path: &Path, mode: u32) -> ArtifactClass {
    let executable = mode & 0o111 != 0;
    let name = name_of(path);
    if let Some(t) = elf_type(head) {
        if name.ends_with(".ko") {
            return ArtifactClass::Module;
        }
        return match t {
            ET_EXEC => ArtifactClass::Exe,
            ET_DYN if executable && !name.contains(".so") => ArtifactClass::Exe,
            ET_DYN => ArtifactClass::Lib,
            _ => ArtifactClass::Other,
        };
    }
    if name.ends_with(".ko") || name.ends_with(".ko.xz") || name.ends_with(".ko.zst") || name.ends_with(".ko.gz") {
        return ArtifactClass::Module;
    }
    if head.starts_with(b"#!") {
        return ArtifactClass::Script;
    }
    if name.ends_with(".service") || name.ends_with(".timer") || name.ends_with(".socket") {
        return ArtifactClass::Service;
    }
    if name.starts_with("vmlinuz") {
        return ArtifactClass::Kernel;
    }
    if name.starts_with("initrd") || name.starts_with("initramfs") {
        return ArtifactClass::Initrd;
    }
    if name.ends_with(".efi") || name == "grub.cfg" {
        return ArtifactClass::Boot;
    }
    if name.ends_with(".deb") || name.ends_with(".rpm") {
        return ArtifactClass::Package;
    }
    if name.ends_with(".AppImage") || name.ends_with(".flatpak") {
        return ArtifactClass::Container;
    }
    if executable {
        return ArtifactClass::Script;
    }
    ArtifactClass::Other
}

/// Whether a class is subject to governance by default.
///
/// Data and unclassified files are not admitted or confined; only things the
/// machine can execute, load or boot from are.
pub fn is_governed(class: ArtifactClass) -> bool {
    !matches!(class, ArtifactClass::Other | ArtifactClass::Dataset | ArtifactClass::Config | ArtifactClass::Key)
}
