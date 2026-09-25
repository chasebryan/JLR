//! Turning a path into an EPN record plus evidence.

use crate::dpkg::{DpkgDb, md5_file};
use crate::facts::{Trust, path_facts};
use crate::{MeasureError, classify, open_measured};
use jlr_model::{ArtifactClass, EpnRecord, EvidenceItem, EvidenceKind, ProvenanceRank, Source};
use std::fs::File;
use std::path::{Path, PathBuf};

/// Options for [`observe`].
#[derive(Clone, Debug)]
pub struct ObserveOptions {
    /// Largest file that will be measured.
    pub max_size: u64,
    /// Owners and groups, besides root, whose write access is acceptable.
    pub trust: Trust,
    /// Seconds since the Unix epoch, recorded as the discovery time.
    pub now: u64,
}

impl Default for ObserveOptions {
    fn default() -> Self {
        Self { max_size: 512 * 1024 * 1024, trust: Trust::root_only(), now: 0 }
    }
}

/// The result of observing one file.
#[derive(Debug)]
pub struct Observation {
    /// The descriptor that was hashed. Execute this, not the path.
    pub file: File,
    /// Immutable identity record.
    pub record: EpnRecord,
    /// Evidence gathered at this moment.
    pub evidence: Vec<EvidenceItem>,
    /// The path that was observed.
    pub path: PathBuf,
}

fn item(kind: EvidenceKind, source: &str, at: u64, detail: &str) -> EvidenceItem {
    EvidenceItem { kind, source: source.into(), at, detail: detail.into(), digest: None }
}

/// Measures `path`, classifies it and collects facts and package-manager evidence.
///
/// The provenance recorded here never exceeds what was actually established:
/// a file merely listed by dpkg is `SourceKnown`, because dpkg's database is
/// unauthenticated. Stronger provenance arrives only through signed baselines,
/// pinned vendor signatures or verified package signatures.
pub fn observe(path: &Path, dpkg: Option<&mut DpkgDb>, opts: &ObserveOptions) -> Result<Observation, MeasureError> {
    let (file, m) = open_measured(path, opts.max_size)?;
    observe_measured(file, m, path, dpkg, opts)
}

/// Like [`observe`], for a descriptor the caller already holds, such as the file
/// descriptor a fanotify permission event delivers for an `exec`.
///
/// `path` is only a label for classification and package lookup; the bytes are
/// measured through `file`, so a path swapped afterwards changes nothing.
pub fn observe_open(
    mut file: File,
    path: &Path,
    dpkg: Option<&mut DpkgDb>,
    opts: &ObserveOptions,
) -> Result<Observation, MeasureError> {
    let m = crate::measure_file(&mut file, opts.max_size)?;
    observe_measured(file, m, path, dpkg, opts)
}

fn observe_measured(
    mut file: File,
    m: crate::Measured,
    path: &Path,
    dpkg: Option<&mut DpkgDb>,
    opts: &ObserveOptions,
) -> Result<Observation, MeasureError> {
    let class = classify(&m.head, path, m.mode);
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    let real_str = real.to_string_lossy().into_owned();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();

    let mut evidence =
        vec![item(EvidenceKind::ContentDigestMatch, "measure", opts.now, "hashed through the open descriptor")];
    let mut provenance = ProvenanceRank::Unknown;
    let mut source = Source { channel: "unmanaged".into(), origin: None, path: Some(real_str.clone()) };
    let mut version = None;

    if let Some(db) = dpkg
        && let Some(own) = db.ownership(&real_str)
    {
        source.channel = "dpkg".into();
        source.origin = Some(own.package.clone());
        version = Some(own.version.clone());
        provenance = ProvenanceRank::SourceKnown;
        evidence.push(item(EvidenceKind::ManagedInstaller, "dpkg", opts.now, &format!("owned by {}", own.package)));
        match own.manifest_md5 {
            Some(expected) => {
                let actual = md5_file(&mut file)?;
                if actual == expected {
                    evidence.push(item(
                        EvidenceKind::PackageManifestMatch,
                        "dpkg",
                        opts.now,
                        "matches the local package manifest (unauthenticated)",
                    ));
                } else {
                    evidence.push(item(
                        EvidenceKind::ContentDigestMismatch,
                        "dpkg",
                        opts.now,
                        "differs from the local package manifest",
                    ));
                }
            }
            None => {
                evidence.push(item(EvidenceKind::Missing, "dpkg", opts.now, "package lists no checksum for this file"));
            }
        }
    }

    match path_facts(path, &opts.trust) {
        Ok(f) => {
            if f.setuid || f.setgid {
                evidence.push(item(EvidenceKind::SetuidBit, "measure", opts.now, "setuid or setgid bit is set"));
            }
            if f.writable_by_untrusted {
                evidence.push(item(
                    EvidenceKind::WritablePath,
                    "measure",
                    opts.now,
                    "file or a parent directory is writable by an untrusted actor",
                ));
            }
        }
        Err(e) => {
            evidence.push(item(EvidenceKind::Missing, "measure", opts.now, &format!("path facts unavailable: {e}")))
        }
    }

    let record = EpnRecord {
        schema: EpnRecord::SCHEMA,
        class,
        name,
        version,
        size: m.size,
        digest: m.digest,
        provenance,
        signer: None,
        source,
        dependencies: Vec::new(),
    };
    let _ = ArtifactClass::Other;
    Ok(Observation { file, record, evidence, path: real })
}
