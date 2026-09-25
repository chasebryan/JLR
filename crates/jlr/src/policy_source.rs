//! Human-authored policy files (TOML) and their compilation to [`Policy`].
//!
//! TOML never enters the trust path: the file is compiled, validated and
//! signed, and only the signed canonical CBOR is ever loaded by the engine.

use jlr_model::{AdmissionState, ArtifactClass, CellClass, EvidenceKind, NetworkMode, ProvenanceRank, ReasonCode};
use jlr_policy::{Policy, Tier};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TierSource {
    pub name: String,
    #[serde(default)]
    pub classes: Vec<String>,
    pub max_provenance: String,
    #[serde(default)]
    pub require_evidence: Vec<String>,
    pub state: String,
    pub cell: String,
    pub network: String,
    #[serde(default)]
    pub needs_user: bool,
    pub reason: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySource {
    pub name: String,
    pub epoch: u64,
    #[serde(default)]
    pub block_classes: Vec<String>,
    pub setuid_min_provenance: String,
    pub writable_path_max_cell: String,
    pub max_manual_cell: String,
    pub evidence_max_age_secs: u64,
    #[serde(rename = "tier")]
    pub tiers: Vec<TierSource>,
}

fn parse<T>(what: &str, s: &str, f: impl Fn(&str) -> Option<T>) -> Result<T, String> {
    f(s).ok_or_else(|| format!("unknown {what} {s:?}"))
}

fn list<T>(what: &str, v: &[String], f: impl Fn(&str) -> Option<T> + Copy) -> Result<Vec<T>, String> {
    v.iter().map(|s| parse(what, s, f)).collect()
}

impl PolicySource {
    /// Compiles to a validated policy.
    pub fn compile(&self) -> Result<Policy, String> {
        let mut tiers = Vec::new();
        for t in &self.tiers {
            tiers.push(Tier {
                name: t.name.clone(),
                classes: list("artifact class", &t.classes, ArtifactClass::parse)?,
                max_provenance: parse("provenance", &t.max_provenance, ProvenanceRank::parse)?,
                require_evidence: list("evidence kind", &t.require_evidence, EvidenceKind::parse)?,
                state: parse("state", &t.state, AdmissionState::parse)?,
                cell: parse("cell", &t.cell, CellClass::parse)?,
                network: parse("network mode", &t.network, NetworkMode::parse)?,
                needs_user: t.needs_user,
                reason: parse("reason code", &t.reason, ReasonCode::parse)?,
            });
        }
        let p = Policy {
            schema: Policy::SCHEMA,
            name: self.name.clone(),
            epoch: self.epoch,
            tiers,
            block_classes: list("artifact class", &self.block_classes, ArtifactClass::parse)?,
            setuid_min_provenance: parse("provenance", &self.setuid_min_provenance, ProvenanceRank::parse)?,
            writable_path_max_cell: parse("cell", &self.writable_path_max_cell, CellClass::parse)?,
            max_manual_cell: parse("cell", &self.max_manual_cell, CellClass::parse)?,
            evidence_max_age_secs: self.evidence_max_age_secs,
        };
        p.validate().map_err(|e| e.to_string())?;
        Ok(p)
    }

    /// The authoring form of a compiled policy.
    pub fn from_policy(p: &Policy) -> PolicySource {
        PolicySource {
            name: p.name.clone(),
            epoch: p.epoch,
            block_classes: p.block_classes.iter().map(ToString::to_string).collect(),
            setuid_min_provenance: p.setuid_min_provenance.to_string(),
            writable_path_max_cell: p.writable_path_max_cell.to_string(),
            max_manual_cell: p.max_manual_cell.to_string(),
            evidence_max_age_secs: p.evidence_max_age_secs,
            tiers: p
                .tiers
                .iter()
                .map(|t| TierSource {
                    name: t.name.clone(),
                    classes: t.classes.iter().map(ToString::to_string).collect(),
                    max_provenance: t.max_provenance.to_string(),
                    require_evidence: t.require_evidence.iter().map(ToString::to_string).collect(),
                    state: t.state.to_string(),
                    cell: t.cell.to_string(),
                    network: t.network.to_string(),
                    needs_user: t.needs_user,
                    reason: t.reason.to_string(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_policies_round_trip_through_toml() {
        for p in [Policy::workstation(3), Policy::strict(9)] {
            let text = toml::to_string_pretty(&PolicySource::from_policy(&p)).unwrap();
            let back: PolicySource = toml::from_str(&text).unwrap();
            let compiled = back.compile().unwrap();
            assert_eq!(compiled, p);
            assert_eq!(compiled.digest(), p.digest(), "the compiled policy must be byte-identical");
        }
    }

    #[test]
    fn unknown_fields_and_names_are_errors() {
        let good = toml::to_string_pretty(&PolicySource::from_policy(&Policy::strict(2))).unwrap();
        assert!(toml::from_str::<PolicySource>(&format!("{good}\nextra = 1\n")).is_err());
        let bad = good.replace("\"ADMITTED\"", "\"TRUSTED\"");
        assert!(toml::from_str::<PolicySource>(&bad).unwrap().compile().is_err());
    }

    #[test]
    fn unsafe_policies_do_not_compile() {
        let mut src = PolicySource::from_policy(&Policy::workstation(1));
        let last = src.tiers.len() - 1;
        src.tiers[last].state = "ADMITTED".into();
        src.tiers[last].cell = "CELL-2".into();
        assert!(src.compile().is_err(), "a catch-all that admits must be refused by validation");
    }
}
