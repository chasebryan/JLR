use super::merkle::*;
use jlr_crypto::Digest;

fn leaves(n: usize) -> Vec<Digest> {
    (0..n).map(|i| leaf_hash(format!("leaf-{i}").as_bytes())).collect()
}

fn tree_of(n: usize) -> Tree {
    let mut t = Tree::new();
    for l in leaves(n) {
        t.push(l);
    }
    t
}

// RFC 6962/9162 reference: 8 leaves d0..d7 = the standard test data.
#[test]
fn certificate_transparency_reference_roots() {
    let data: [&[u8]; 8] = [
        b"",
        b"\x00",
        b"\x10",
        b"\x20\x21",
        b"\x30\x31",
        b"\x40\x41\x42\x43",
        b"\x50\x51\x52\x53\x54\x55\x56\x57",
        b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
    ];
    // Roots published with the Certificate Transparency reference test vectors.
    let roots = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];
    assert_eq!(empty_root().hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    let mut t = Tree::new();
    for (i, d) in data.iter().enumerate() {
        t.push(leaf_hash(d));
        assert_eq!(t.root().hex(), roots[i], "root after {} leaves", i + 1);
        assert_eq!(t.root_at(i + 1).unwrap(), t.root());
    }
}

#[test]
fn incremental_root_matches_recursive_definition_for_all_sizes() {
    let all = leaves(70);
    let mut t = Tree::new();
    assert_eq!(t.root(), empty_root());
    for (i, l) in all.iter().enumerate() {
        t.push(*l);
        assert_eq!(t.root(), root_of(&all[..=i]), "size {}", i + 1);
    }
}

#[test]
fn every_inclusion_proof_verifies_and_rejects_tampering() {
    for size in 1..=40usize {
        let t = tree_of(size);
        let root = t.root();
        for index in 0..size {
            let proof = t.inclusion_proof(index, size).unwrap();
            let leaf = *t.leaf(index).unwrap();
            assert!(verify_inclusion(&leaf, index, size, &proof, &root), "size {size} index {index}");
            // wrong index, wrong leaf, wrong size, wrong root, altered proof
            if size > 1 {
                assert!(
                    !verify_inclusion(&leaf, (index + 1) % size, size, &proof, &root) || (index + 1) % size == index
                );
            }
            assert!(!verify_inclusion(&leaf_hash(b"other"), index, size, &proof, &root));
            // Note: a root does not commit to the tree size, so verify_inclusion cannot reject
            // a different `size` on its own. Verifiers must take (size, root) together from a
            // signed checkpoint, which is what the ledger does.
            assert!(!verify_inclusion(&leaf, index, size, &proof, &leaf_hash(b"bad root")));
            if let Some(first) = proof.first() {
                let mut bad = proof.clone();
                bad[0] = Digest([first.0[0] ^ 1; 32]);
                assert!(!verify_inclusion(&leaf, index, size, &bad, &root));
                let mut long = proof.clone();
                long.push(*first);
                assert!(!verify_inclusion(&leaf, index, size, &long, &root));
                let short = &proof[..proof.len() - 1];
                assert!(!verify_inclusion(&leaf, index, size, short, &root));
            }
        }
    }
}

#[test]
fn every_consistency_proof_verifies_and_rejects_tampering() {
    for second in 1..=40usize {
        let t = tree_of(second);
        let second_root = t.root();
        for first in 1..=second {
            let first_root = t.root_at(first).unwrap();
            let proof = t.consistency_proof(first, second).unwrap();
            assert!(
                verify_consistency(first, second, &first_root, &second_root, &proof),
                "first {first} second {second}"
            );
            let wrong = leaf_hash(b"wrong");
            assert!(!verify_consistency(first, second, &wrong, &second_root, &proof));
            assert!(!verify_consistency(first, second, &first_root, &wrong, &proof));
            if first < second {
                let mut bad = proof.clone();
                if let Some(p) = bad.first_mut() {
                    p.0[0] ^= 1;
                    assert!(!verify_consistency(first, second, &first_root, &second_root, &bad));
                }
                // A tree whose history was rewritten is not consistent with the old root.
                let mut forged = Tree::new();
                for (i, l) in leaves(second).into_iter().enumerate() {
                    forged.push(if i == 0 { leaf_hash(b"rewritten") } else { l });
                }
                assert!(!verify_consistency(first, second, &first_root, &forged.root(), &proof));
            }
        }
    }
}

#[test]
fn consistency_edge_cases() {
    let t = tree_of(5);
    assert!(verify_consistency(0, 5, &empty_root(), &t.root(), &[]));
    assert!(!verify_consistency(0, 5, &leaf_hash(b"x"), &t.root(), &[]));
    assert!(verify_consistency(5, 5, &t.root(), &t.root(), &[]));
    assert!(!verify_consistency(6, 5, &t.root(), &t.root(), &[]));
    assert!(t.consistency_proof(3, 9).is_none());
    assert!(t.inclusion_proof(5, 5).is_none());
    assert!(t.inclusion_proof(0, 9).is_none());
}

#[test]
fn leaf_and_node_hashes_are_domain_separated() {
    let a = leaf_hash(b"a");
    let b = leaf_hash(b"b");
    let node = node_hash(&a, &b);
    // A leaf whose content is the concatenation of two child hashes must not
    // equal the interior node over them.
    let mut concat = a.0.to_vec();
    concat.extend_from_slice(&b.0);
    assert_ne!(leaf_hash(&concat), node);
}
