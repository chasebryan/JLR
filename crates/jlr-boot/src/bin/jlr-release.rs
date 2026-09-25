//! Build-time release tooling: keys, trust anchors, signed manifests, boot state.
//!
//! Signing keys never belong on the machines that boot the result. Run this
//! tool on a separate, preferably offline, build machine.

#![forbid(unsafe_code)]

use jlr_boot::{BootState, Component, ReleaseManifest, verify_image, verify_manifest};
use jlr_cbor::Cbor;
use jlr_crypto::{Digest, PublicKey, Role, SigningKeypair, TrustAnchors};
use std::fs::File;
use std::path::PathBuf;

fn usage() -> ! {
    eprintln!(
        "usage:
  jlr-release keygen --role <root|release|policy|recovery|device> --out KEYFILE
  jlr-release pubkey KEYFILE --out PUBFILE
  jlr-release anchors --out ANCHORS PUBFILE...
  jlr-release manifest --key KEYFILE --image IMG --name N --version V --epoch E [--min-epoch M] [--component NAME=FILE]... --out MANIFEST
  jlr-release verify --anchors ANCHORS --manifest MANIFEST [--image IMG] [--floor N]
  jlr-release state --out FILE [--install SLOT]... [--floor N]"
    );
    std::process::exit(2);
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn args_all(args: &[String], name: &str) -> Vec<String> {
    args.iter().enumerate().filter(|(_, a)| *a == name).filter_map(|(i, _)| args.get(i + 1)).cloned().collect()
}

fn need(args: &[String], name: &str) -> String {
    arg(args, name).unwrap_or_else(|| {
        eprintln!("missing {name}");
        usage()
    })
}

fn positional(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
        } else if a.starts_with("--") {
            skip = true;
        } else {
            out.push(a.clone());
        }
    }
    out
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else { usage() };
    let rest = &args[1..];
    match cmd.as_str() {
        "keygen" => {
            let role = Role::parse(&need(rest, "--role")).ok_or("unknown role")?;
            let out = PathBuf::from(need(rest, "--out"));
            let key = SigningKeypair::generate(role).map_err(|e| e.to_string())?;
            key.save(&out).map_err(|e| e.to_string())?;
            println!("{} key {} written to {} (mode 0600)", role, key.public().id(), out.display());
            Ok(())
        }
        "pubkey" => {
            let key = SigningKeypair::load(&PathBuf::from(positional(rest).first().ok_or("missing KEYFILE")?))
                .map_err(|e| e.to_string())?;
            std::fs::write(need(rest, "--out"), key.public().to_cbor()).map_err(|e| e.to_string())?;
            println!("public key {} ({})", key.public().id(), key.role());
            Ok(())
        }
        "anchors" => {
            let mut a = TrustAnchors::new();
            for p in positional(rest) {
                let bytes = std::fs::read(&p).map_err(|e| format!("{p}: {e}"))?;
                a.insert(PublicKey::from_cbor(&bytes).map_err(|e| format!("{p}: {e}"))?);
            }
            std::fs::write(need(rest, "--out"), a.to_cbor()).map_err(|e| e.to_string())?;
            println!("{} trust anchors written", a.len());
            Ok(())
        }
        "manifest" => {
            let key = SigningKeypair::load(&PathBuf::from(need(rest, "--key"))).map_err(|e| e.to_string())?;
            let image = PathBuf::from(need(rest, "--image"));
            let bytes = std::fs::read(&image).map_err(|e| format!("{}: {e}", image.display()))?;
            let epoch: u64 = need(rest, "--epoch").parse().map_err(|_| "bad --epoch")?;
            let min_epoch: u64 =
                arg(rest, "--min-epoch").map_or(Ok(epoch), |v| v.parse()).map_err(|_| "bad --min-epoch")?;
            let mut components = Vec::new();
            for c in args_all(rest, "--component") {
                let (name, path) = c.split_once('=').ok_or("--component needs NAME=FILE")?;
                let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
                components.push(Component { name: name.to_owned(), digest: Digest::of(&data) });
            }
            let m = ReleaseManifest {
                schema: ReleaseManifest::SCHEMA,
                name: need(rest, "--name"),
                version: need(rest, "--version"),
                epoch,
                image_digest: Digest::of(&bytes),
                image_size: bytes.len() as u64,
                min_epoch,
                policy_digest: None,
                components,
            };
            let signed = m.sign(&key);
            std::fs::write(need(rest, "--out"), &signed).map_err(|e| e.to_string())?;
            println!(
                "manifest {} {} epoch {} image {} ({} bytes), signed by {}",
                m.name,
                m.version,
                m.epoch,
                m.image_digest,
                m.image_size,
                key.public().id()
            );
            Ok(())
        }
        "verify" => {
            let anchors = TrustAnchors::from_cbor(&std::fs::read(need(rest, "--anchors")).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            let bytes = std::fs::read(need(rest, "--manifest")).map_err(|e| e.to_string())?;
            let floor: u64 = arg(rest, "--floor").map_or(Ok(0), |v| v.parse()).map_err(|_| "bad --floor")?;
            let m = verify_manifest(&bytes, &anchors, floor).map_err(|e| e.to_string())?;
            println!("manifest OK: {} {} epoch {}", m.name, m.version, m.epoch);
            if let Some(img) = arg(rest, "--image") {
                let mut f = File::open(&img).map_err(|e| format!("{img}: {e}"))?;
                let n = verify_image(&m, &mut f, &mut std::io::sink()).map_err(|e| e.to_string())?;
                println!("image OK: {n} bytes match the manifest digest");
            }
            Ok(())
        }
        "state" => {
            let mut s = BootState::fresh();
            for slot in args_all(rest, "--install") {
                s.install(&slot);
            }
            if let Some(f) = arg(rest, "--floor") {
                s.floor = f.parse().map_err(|_| "bad --floor")?;
            }
            std::fs::write(need(rest, "--out"), s.to_cbor()).map_err(|e| e.to_string())?;
            println!(
                "boot state written: floor {}, slots {:?}",
                s.floor,
                s.slots.iter().map(|x| (&x.name, x.priority, x.tries, x.successful)).collect::<Vec<_>>()
            );
            Ok(())
        }
        _ => usage(),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("jlr-release: {e}");
        std::process::exit(1);
    }
}
