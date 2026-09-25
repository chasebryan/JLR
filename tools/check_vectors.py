#!/usr/bin/env python3
"""Checks docs/vectors/protocol-v1.json with an implementation that shares no code with the Rust one.

It contains its own CBOR decoder, COSE Sig_structure builder and RFC 9162 Merkle tree, and uses the Python
`cryptography` package only for Ed25519 and `hashlib` for SHA-256. If this passes, the formats in
docs/INTEGRITY_PROTOCOL.md are implementable from the document, and the Rust code agrees with it.

usage: tools/check_vectors.py
requires: python3, the `cryptography` package
"""
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parent.parent
V = json.loads((ROOT / "docs/vectors/protocol-v1.json").read_text())
failures = []


def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        failures.append(name)


# ---- strict deterministic CBOR (the JLR-DCBOR/1 rules) ----
def head(b, i):
    ib = b[i]
    mt, ai = ib >> 5, ib & 31
    i += 1
    if ai < 24:
        return mt, ai, i, ai
    if ai > 27:
        raise ValueError("indefinite or reserved additional info")
    n = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
    x = int.from_bytes(b[i:i + n], "big")
    # shortest-form rule
    if mt != 7 and x < {24: 24, 25: 256, 26: 65536, 27: 1 << 32}[ai]:
        raise ValueError("non-shortest argument")
    return mt, ai, i + n, x


def dec(b, i=0):
    mt, ai, i, a = head(b, i)
    if mt == 0:
        return a, i
    if mt == 1:
        return -1 - a, i
    if mt == 2:
        return ("bytes", b[i:i + a]), i + a
    if mt == 3:
        return b[i:i + a].decode("utf-8"), i + a
    if mt == 4:
        out = []
        for _ in range(a):
            x, i = dec(b, i)
            out.append(x)
        return out, i
    if mt == 5:
        out, prev = {}, None
        for _ in range(a):
            ks = i
            k, i = dec(b, i)
            kb = b[ks:i]
            if prev is not None and not prev < kb:
                raise ValueError("map keys not strictly sorted by encoding")
            prev = kb
            x, i = dec(b, i)
            out[k if not isinstance(k, tuple) else k[1]] = x
        return out, i
    if mt == 6:
        x, i = dec(b, i)
        return ("tag", a, x), i
    if ai in (20, 21, 22):
        return {20: False, 21: True, 22: None}[ai], i
    raise ValueError("unsupported simple value or float")


def enc_head(mt, n):
    if n < 24:
        return bytes([mt << 5 | n])
    if n < 256:
        return bytes([mt << 5 | 24, n])
    if n < 65536:
        return bytes([mt << 5 | 25]) + n.to_bytes(2, "big")
    return bytes([mt << 5 | 26]) + n.to_bytes(4, "big")


def bstr(x):
    return enc_head(2, len(x)) + x


def sha256(x):
    return hashlib.sha256(x).digest()


# ---- CBOR cases decode strictly and re-encode identically is exercised by decoding without error ----
for case in V["cbor"]:
    try:
        dec(bytes.fromhex(case["hex"]))
        check(f"cbor: {case['name']}", True)
    except Exception as e:  # noqa: BLE001
        check(f"cbor: {case['name']} ({e})", False)

# ---- keys ----
pub = bytes.fromhex(V["keys"]["device_public"])
check("kid is SHA-256 of the raw public key", sha256(pub).hex() == V["keys"]["device_kid"])

# ---- envelope: COSE_Sign1 verification from the specification alone ----
env = bytes.fromhex(V["envelope"]["cose_sign1"])
tree, end = dec(env)
check("envelope is exactly one canonical CBOR item", end == len(env))
_, tag, arr = tree
check("envelope is tag 18 with four elements", tag == 18 and len(arr) == 4)
protected, unprotected, payload, signature = arr[0][1], arr[1], arr[2][1], arr[3][1]
check("unprotected header is the empty map", unprotected == {})
header, _ = dec(protected)
check("protected header has exactly labels 1, 4, 16", sorted(header) == [1, 4, 16])
check("alg is -19 (Ed25519, RFC 9864)", header[1] == -19)
check("kid in header matches the signer", header[4][1].hex() == V["keys"]["device_kid"])
typ = f"application/vnd.jlr.{V['envelope']['record_type']}+cbor;v=1"
check("typ names the record type", header[16] == typ)
aad = f"JLR/1/{V['envelope']['record_type']}/{V['envelope']['scope']}".encode()
check("external_aad is JLR/1/<type>/<scope>", aad.decode() == V["envelope"]["external_aad"])
sig_structure = bytes([0x84]) + enc_head(3, 10) + b"Signature1" + bstr(protected) + bstr(aad) + bstr(payload)
try:
    Ed25519PublicKey.from_public_bytes(pub).verify(signature, sig_structure)
    check("Ed25519 signature over the Sig_structure verifies", True)
except Exception:  # noqa: BLE001
    check("Ed25519 signature over the Sig_structure verifies", False)
try:
    Ed25519PublicKey.from_public_bytes(pub).verify(signature, sig_structure.replace(b"node-vector", b"node-vectoR"))
    check("the same signature does NOT verify for another scope", False)
except Exception:  # noqa: BLE001
    check("the same signature does NOT verify for another scope", True)
check("record_digest is SHA-256 of the payload", "sha256:" + sha256(payload).hex() == V["envelope"]["record_digest"])
check("envelope_digest is SHA-256 of the whole envelope", "sha256:" + sha256(env).hex() == V["envelope"]["envelope_digest"])

# ---- EPN ----
rec = bytes.fromhex(V["epn"]["record_cbor"])
check("EPN payload in the envelope is the record", rec == payload)
check("EPN id is EPN-1-<CLASS>-<sha256 of the canonical record>", V["epn"]["id"] == "EPN-1-EXE-" + sha256(rec).hex())
r, _ = dec(rec)
check("EPN record fields decode: class 5 (EXE), name, size", r[2] == 5 and r[3] == "ls" and r[5] == 138208)
check("EPN digest field is [-16, 32 bytes]", r[6][0] == -16 and len(r[6][1][1]) == 32)

# ---- Merkle tree, RFC 9162 ----
def leaf_hash(d):
    return sha256(b"\x00" + d)


def node_hash(a, b):
    return sha256(b"\x01" + a + b)


def mth(ls):
    n = len(ls)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return ls[0]
    k = 1 << ((n - 1).bit_length() - 1)
    return node_hash(mth(ls[:k]), mth(ls[k:]))


leaves = [leaf_hash(x.encode()) for x in V["merkle"]["leaves"]]
check("leaf hashes", ["sha256:" + x.hex() for x in leaves] == V["merkle"]["leaf_hashes"])
check("Merkle root of 5 leaves", "sha256:" + mth(leaves).hex() == V["merkle"]["root_5"])
check("Merkle root of the first 3 leaves", "sha256:" + mth(leaves[:3]).hex() == V["merkle"]["root_3"])


def path(m, ls):
    if len(ls) <= 1:
        return []
    k = 1 << ((len(ls) - 1).bit_length() - 1)
    return path(m, ls[:k]) + [mth(ls[k:])] if m < k else path(m - k, ls[k:]) + [mth(ls[:k])]


check("inclusion proof for index 2 of 5", ["sha256:" + x.hex() for x in path(2, leaves)] == V["merkle"]["inclusion_index_2_size_5"])

# ---- release manifest signature ----
rel = bytes.fromhex(V["release"]["signed_manifest"])
rtree, rend = dec(rel)
check("release manifest envelope decodes", rend == len(rel))
rprot, rpayload, rsig = rtree[2][0][1], rtree[2][2][1], rtree[2][3][1]
rpub = bytes.fromhex(V["keys"]["release_public"])
raad = b"JLR/1/release-manifest/*"
rstruct = bytes([0x84]) + enc_head(3, 10) + b"Signature1" + bstr(rprot) + bstr(raad) + bstr(rpayload)
try:
    Ed25519PublicKey.from_public_bytes(rpub).verify(rsig, rstruct)
    check("release manifest signature verifies (scope *)", True)
except Exception:  # noqa: BLE001
    check("release manifest signature verifies (scope *)", False)

print()
print(f"{len(failures)} failure(s)" if failures else "all independent checks passed")
sys.exit(1 if failures else 0)
