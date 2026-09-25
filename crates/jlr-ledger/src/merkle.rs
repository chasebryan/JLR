//! Merkle tree hashing, inclusion proofs and consistency proofs (RFC 9162 section 2).
//!
//! Leaf hashes are `SHA-256(0x00 || data)` and interior nodes are
//! `SHA-256(0x01 || left || right)`, so a leaf can never be mistaken for a node.

use jlr_crypto::Digest;
use sha2::{Digest as _, Sha256};

/// Hash of a leaf.
pub fn leaf_hash(data: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    Digest(h.finalize().into())
}

/// Hash of an interior node.
pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left.0);
    h.update(right.0);
    Digest(h.finalize().into())
}

/// Root of the empty tree.
pub fn empty_root() -> Digest {
    Digest::of(b"")
}

/// Largest power of two strictly smaller than `n` (requires `n >= 2`).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// Root of the subtree over `leaves`.
pub fn root_of(leaves: &[Digest]) -> Digest {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root_of(&leaves[..k]), &root_of(&leaves[k..]))
        }
    }
}

/// An append-only Merkle tree that keeps its leaf hashes.
#[derive(Clone, Debug, Default)]
pub struct Tree {
    leaves: Vec<Digest>,
    /// `roots[n - 1]` is the root of the first `n` leaves, so any prefix root is O(1).
    roots: Vec<Digest>,
    /// Roots of the perfect subtrees covering the leaves, largest first,
    /// as `(height, hash)`. Lets the current root be computed incrementally.
    peaks: Vec<(u32, Digest)>,
}

impl Tree {
    /// An empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves.
    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    /// Appends an already-hashed leaf.
    pub fn push(&mut self, leaf: Digest) {
        self.leaves.push(leaf);
        let mut height = 0u32;
        let mut hash = leaf;
        while let Some(&(h, left)) = self.peaks.last() {
            if h != height {
                break;
            }
            self.peaks.pop();
            hash = node_hash(&left, &hash);
            height += 1;
        }
        self.peaks.push((height, hash));
        let root = self.root();
        self.roots.push(root);
    }

    /// Current root in O(log n).
    pub fn root(&self) -> Digest {
        let mut it = self.peaks.iter().rev();
        let Some(&(_, mut acc)) = it.next() else { return empty_root() };
        for &(_, left) in it {
            acc = node_hash(&left, &acc);
        }
        acc
    }

    /// Root of the first `size` leaves.
    pub fn root_at(&self, size: usize) -> Option<Digest> {
        match size {
            0 => Some(empty_root()),
            n if n <= self.size() => Some(self.roots[n - 1]),
            _ => None,
        }
    }

    /// Leaf hash at `index`.
    pub fn leaf(&self, index: usize) -> Option<&Digest> {
        self.leaves.get(index)
    }

    /// Audit path proving that leaf `index` is in the tree of `size` leaves.
    pub fn inclusion_proof(&self, index: usize, size: usize) -> Option<Vec<Digest>> {
        if size > self.size() || index >= size {
            return None;
        }
        Some(path(index, &self.leaves[..size]))
    }

    /// Proof that the tree of `first` leaves is a prefix of the tree of `second`.
    pub fn consistency_proof(&self, first: usize, second: usize) -> Option<Vec<Digest>> {
        if second > self.size() || first > second {
            return None;
        }
        if first == 0 || first == second {
            return Some(Vec::new());
        }
        Some(subproof(first, &self.leaves[..second], true))
    }
}

fn path(m: usize, d: &[Digest]) -> Vec<Digest> {
    if d.len() <= 1 {
        return Vec::new();
    }
    let k = split(d.len());
    if m < k {
        let mut p = path(m, &d[..k]);
        p.push(root_of(&d[k..]));
        p
    } else {
        let mut p = path(m - k, &d[k..]);
        p.push(root_of(&d[..k]));
        p
    }
}

fn subproof(m: usize, d: &[Digest], b: bool) -> Vec<Digest> {
    let n = d.len();
    if m == n {
        return if b { Vec::new() } else { vec![root_of(d)] };
    }
    let k = split(n);
    if m <= k {
        let mut p = subproof(m, &d[..k], b);
        p.push(root_of(&d[k..]));
        p
    } else {
        let mut p = subproof(m - k, &d[k..], false);
        p.push(root_of(&d[..k]));
        p
    }
}

/// Verifies an inclusion proof (RFC 9162 section 2.1.3.2).
pub fn verify_inclusion(leaf: &Digest, index: usize, size: usize, proof: &[Digest], root: &Digest) -> bool {
    if index >= size {
        return false;
    }
    let mut fnode = index;
    let mut snode = size - 1;
    let mut r = *leaf;
    for p in proof {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && r == *root
}

/// Verifies a consistency proof (RFC 9162 section 2.1.4.2).
pub fn verify_consistency(
    first: usize,
    second: usize,
    first_root: &Digest,
    second_root: &Digest,
    proof: &[Digest],
) -> bool {
    if first > second {
        return false;
    }
    if first == second {
        return proof.is_empty() && first_root == second_root;
    }
    if first == 0 {
        // The empty tree is a prefix of every tree.
        return proof.is_empty() && *first_root == empty_root();
    }
    let mut nodes: Vec<Digest> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        nodes.push(*first_root);
    }
    nodes.extend_from_slice(proof);
    if nodes.is_empty() {
        return false;
    }
    let mut fnode = first - 1;
    let mut snode = second - 1;
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    let mut fr = nodes[0];
    let mut sr = nodes[0];
    for c in &nodes[1..] {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    fr == *first_root && sr == *second_root && snode == 0
}
