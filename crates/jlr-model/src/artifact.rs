//! Artifact identity: classes, provenance ranking and the EPN record.

use jlr_cbor::{Cbor, record};
use jlr_crypto::Digest;
use std::fmt;

macro_rules! coded_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident : $repr:ty {
            $( $(#[$vmeta:meta])* $variant:ident = $code:literal => $text:literal ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
        $vis enum $name {
            $( $(#[$vmeta])* $variant = $code ),*
        }

        impl $name {
            /// Every variant in code order.
            pub const ALL: &'static [$name] = &[ $( $name::$variant ),* ];

            /// Stable upper-case name used in logs, policy files and EPN identifiers.
            pub fn as_str(self) -> &'static str {
                match self { $( $name::$variant => $text ),* }
            }

            /// Parses [`Self::as_str`], case-insensitively.
            pub fn parse(s: &str) -> ::core::option::Option<Self> {
                $( if s.eq_ignore_ascii_case($text) { return ::core::option::Option::Some($name::$variant); } )*
                ::core::option::Option::None
            }

            /// Numeric wire code.
            pub fn code(self) -> $repr { self as $repr }

            /// Looks up a wire code.
            pub fn from_code(c: $repr) -> ::core::option::Option<Self> {
                match c { $( $code => ::core::option::Option::Some($name::$variant), )* _ => ::core::option::Option::None }
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result { f.write_str(self.as_str()) }
        }

        impl ::jlr_cbor::Cbor for $name {
            fn to_value(&self) -> ::jlr_cbor::Value { ::jlr_cbor::Value::Uint(u64::from(self.code())) }
            fn from_value(v: &::jlr_cbor::Value) -> ::core::result::Result<Self, ::jlr_cbor::Error> {
                let n = <$repr>::try_from(v.as_u64()?).map_err(|_| ::jlr_cbor::Error::OutOfRange)?;
                Self::from_code(n).ok_or(::jlr_cbor::Error::Invalid(concat!("unknown ", stringify!($name))))
            }
        }
    };
}
pub(crate) use coded_enum;

coded_enum! {
    /// What kind of governed object an EPN describes.
    pub enum ArtifactClass: u8 {
        /// Bootloader or boot configuration.
        Boot = 1 => "BOOT",
        /// Kernel image.
        Kernel = 2 => "KERNEL",
        /// Initial RAM filesystem.
        Initrd = 3 => "INITRD",
        /// Kernel module.
        Module = 4 => "MODULE",
        /// Executable file.
        Exe = 5 => "EXE",
        /// Shared library.
        Lib = 6 => "LIB",
        /// Interpreted script.
        Script = 7 => "SCRIPT",
        /// Service or unit definition.
        Service = 8 => "SERVICE",
        /// Configuration file.
        Config = 9 => "CONFIG",
        /// Software package.
        Package = 10 => "PACKAGE",
        /// Container or application bundle.
        Container = 11 => "CONTAINER",
        /// Disk or base image.
        Image = 12 => "IMAGE",
        /// JLR policy bundle.
        Policy = 13 => "POLICY",
        /// Key material reference.
        Key = 14 => "KEY",
        /// Firmware blob.
        Firmware = 15 => "FIRMWARE",
        /// Data set.
        Dataset = 16 => "DATASET",
        /// Recovery artifact.
        Recovery = 17 => "RECOVERY",
        /// Anything else.
        Other = 18 => "OTHER",
    }
}

coded_enum! {
    /// Quality of provenance evidence. A smaller number is stronger.
    pub enum ProvenanceRank: u8 {
        /// Locally rebuilt and reproducibly matched.
        Reproduced = 1 => "REPRODUCED",
        /// Signature from a pinned trusted vendor key.
        PinnedVendor = 2 => "PINNED_VENDOR",
        /// Signature from an approved distribution repository.
        DistroSigned = 3 => "DISTRO_SIGNED",
        /// Upstream checksum received over a trusted channel.
        VerifiedChecksum = 4 => "VERIFIED_CHECKSUM",
        /// Source is known but nothing authenticates the bytes.
        SourceKnown = 5 => "SOURCE_KNOWN",
        /// Nothing is known about where the bytes came from.
        Unknown = 6 => "UNKNOWN",
    }
}

impl ProvenanceRank {
    /// Whether `self` is at least as strong as `required`.
    pub fn satisfies(self, required: ProvenanceRank) -> bool {
        self <= required
    }
}

record! {
    /// Where an artifact was found and how it arrived.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Source {
        /// How the artifact entered the machine, for example `dpkg`, `flatpak`,
        /// `download`, `local-build`, `usb`, `base-image`, `unmanaged`.
        1 => channel: String,
        /// Package or origin name when the channel provides one.
        2 => origin: Option<String>,
        /// Path where this occurrence was found.
        3 => path: Option<String>,
    }
}

record! {
    /// The immutable identity of an artifact. Its EPN identifier is derived
    /// from the SHA-256 of these canonical bytes, so it can be recomputed by
    /// anyone and never changes when local admission state does.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EpnRecord {
        /// Schema version, currently 1.
        1 => schema: u32,
        /// Artifact class.
        2 => class: ArtifactClass,
        /// Canonical name, for example a package name or file basename.
        3 => name: String,
        /// Version string when known.
        4 => version: Option<String>,
        /// Exact size in bytes.
        5 => size: u64,
        /// SHA-256 of the exact content.
        6 => digest: Digest,
        /// Provenance rank established at discovery.
        7 => provenance: ProvenanceRank,
        /// Identifier of the signing key or vendor when provenance depends on a signature.
        8 => signer: Option<String>,
        /// How and where the artifact was found.
        9 => source: Source,
        /// Content digests of dependencies that the admission depends on.
        10 => dependencies: Vec<Digest>,
        /// Seconds since the Unix epoch at first discovery (advisory).
        11 => discovered_at: u64,
    }
}

impl EpnRecord {
    /// Current schema version.
    pub const SCHEMA: u32 = 1;

    /// SHA-256 of the canonical encoding: the record's content identity.
    pub fn digest_of_record(&self) -> Digest {
        Digest::of(&self.to_cbor())
    }

    /// The EPN identifier of this record.
    pub fn id(&self) -> EpnId {
        EpnId { class: self.class, digest: self.digest_of_record() }
    }
}

/// `EPN-1-<CLASS>-<64 hex digits>`.
///
/// The identifier is public. It is not a secret, a password or a key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EpnId {
    /// Class prefix, repeated in the identifier for readability.
    pub class: ArtifactClass,
    /// Content digest of the canonical record.
    pub digest: Digest,
}

impl EpnId {
    /// Parses the textual form.
    pub fn parse(s: &str) -> Option<EpnId> {
        let rest = s.strip_prefix("EPN-1-")?;
        let (class, hex) = rest.split_once('-')?;
        Some(EpnId { class: ArtifactClass::parse(class)?, digest: Digest::from_hex(hex)? })
    }

    /// First sixteen hex digits, for compact display.
    pub fn short(&self) -> String {
        format!("EPN-1-{}-{}", self.class, &self.digest.hex()[..16])
    }
}

impl fmt::Display for EpnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EPN-1-{}-{}", self.class, self.digest.hex())
    }
}
impl fmt::Debug for EpnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
