use super::*;
use proptest::prelude::*;

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

// RFC 8949 Appendix A vectors that fall inside the JLR-DCBOR/1 data model.
#[test]
fn rfc8949_appendix_a_vectors() {
    let cases: Vec<(Value, &str)> = vec![
        (Value::Uint(0), "00"),
        (Value::Uint(1), "01"),
        (Value::Uint(10), "0a"),
        (Value::Uint(23), "17"),
        (Value::Uint(24), "1818"),
        (Value::Uint(25), "1819"),
        (Value::Uint(100), "1864"),
        (Value::Uint(1000), "1903e8"),
        (Value::Uint(1_000_000), "1a000f4240"),
        (Value::Uint(1_000_000_000_000), "1b000000e8d4a51000"),
        (Value::Uint(u64::MAX), "1bffffffffffffffff"),
        (Value::Nint(0), "20"),
        (Value::Nint(9), "29"),
        (Value::Nint(99), "3863"),
        (Value::Nint(999), "3903e7"),
        (Value::Bool(false), "f4"),
        (Value::Bool(true), "f5"),
        (Value::Null, "f6"),
        (Value::Bytes(vec![]), "40"),
        (Value::Bytes(vec![1, 2, 3, 4]), "4401020304"),
        (Value::Text(String::new()), "60"),
        (Value::Text("a".into()), "6161"),
        (Value::Text("IETF".into()), "6449455446"),
        (Value::Text("\"\\".into()), "62225c"),
        (Value::Text("\u{00fc}".into()), "62c3bc"),
        (Value::Text("\u{6c34}".into()), "63e6b0b4"),
        (Value::Array(vec![]), "80"),
        (Value::Array(vec![1u8.into(), 2u8.into(), 3u8.into()]), "83010203"),
        (Value::Map(Map::new()), "a0"),
        (Value::Map(Map::new().with(1u8, 2u8).with(3u8, 4u8)), "a201020304"),
        (Value::Tag(1, Box::new(Value::Uint(1_363_896_240))), "c11a514b67b0"),
    ];
    for (v, h) in cases {
        let bytes = hx(h);
        assert_eq!(encode(&v), bytes, "encode {}", v.diag());
        assert_eq!(decode(&bytes).unwrap(), v, "decode {h}");
    }
}

#[test]
fn map_keys_are_sorted_by_encoded_bytes_regardless_of_insertion_order() {
    // Encoded keys: 10 = 0a, 100 = 1864, -1 = 20, "z" = 617a, "aa" = 626161.
    let expected = hx("a50a011864022003617a0462616105");
    let forward = Map::new().with(10u8, 1u8).with(100u8, 2u8).with(-1i64, 3u8).with("z", 4u8).with("aa", 5u8);
    let scrambled = Map::new().with("aa", 5u8).with(-1i64, 3u8).with(100u8, 2u8).with("z", 4u8).with(10u8, 1u8);
    assert_eq!(encode(&Value::Map(forward)), expected);
    assert_eq!(encode(&Value::Map(scrambled)), expected);
    assert!(decode(&expected).is_ok());
}

#[test]
fn duplicate_key_on_insert_is_an_error() {
    let mut m = Map::new();
    m.insert(1u8, 1u8).unwrap();
    assert_eq!(m.insert(1u8, 2u8), Err(Error::DuplicateKey));
}

#[test]
fn rejects_non_shortest_arguments() {
    for h in [
        "1800",               // 0 as one-byte argument
        "1817",               // 23 as one-byte argument
        "190000",             // 0 as two-byte argument
        "1900ff",             // 255 as two-byte argument
        "1a0000ffff",         // 65535 as four-byte argument
        "1b00000000ffffffff", // u32::MAX as eight-byte argument
        "5800",               // zero-length bytes with one-byte length
        "780161",             // text length 1 with one-byte length
        "9800",               // empty array, long form
        "b800",               // empty map, long form
        "d80001",             // tag 0 with long-form tag number
    ] {
        assert_eq!(decode(&hx(h)), Err(Error::NonShortestArgument), "{h}");
    }
}

#[test]
fn rejects_indefinite_length_items() {
    for h in ["5fff", "7fff", "9fff", "bfff", "9f01ff"] {
        assert_eq!(decode(&hx(h)), Err(Error::IndefiniteLength), "{h}");
    }
}

#[test]
fn rejects_floats_undefined_and_other_simple_values() {
    for h in [
        "f90000",             // half float 0.0
        "fa47c35000",         // single float
        "fb3ff199999999999a", // double float
        "f7",                 // undefined
        "e0",                 // simple(0)
        "f0",                 // simple(16)
        "f820",               // simple(32)
    ] {
        assert_eq!(decode(&hx(h)), Err(Error::UnsupportedSimpleOrFloat), "{h}");
    }
}

#[test]
fn rejects_reserved_additional_info() {
    for h in ["1c", "1d", "1e", "5c", "fc"] {
        assert_eq!(decode(&hx(h)), Err(Error::ReservedAdditionalInfo), "{h}");
    }
}

#[test]
fn rejects_unsorted_and_duplicate_map_keys() {
    // keys 2 then 1: out of order
    assert_eq!(decode(&hx("a202000100")), Err(Error::UnsortedMapKeys));
    // key 1 twice
    assert_eq!(decode(&hx("a201000100")), Err(Error::DuplicateKey));
    // "aa" (626161) before "z" (617a): 0x62.. > 0x61.. so out of order
    assert_eq!(decode(&hx("a2626161006 17a01".replace(' ', "").as_str())), Err(Error::UnsortedMapKeys));
}

#[test]
fn rejects_invalid_utf8_and_truncation_and_trailing_bytes() {
    assert_eq!(decode(&hx("62c328")), Err(Error::InvalidUtf8)); // invalid continuation byte
    assert_eq!(decode(&hx("62ffff")), Err(Error::InvalidUtf8));
    assert_eq!(decode(&hx("")), Err(Error::Truncated));
    assert_eq!(decode(&hx("18")), Err(Error::Truncated));
    assert_eq!(decode(&hx("4401")), Err(Error::LengthExceedsInput));
    assert_eq!(decode(&hx("8301")), Err(Error::LengthExceedsInput));
    assert_eq!(decode(&hx("0000")), Err(Error::TrailingBytes));
    assert_eq!(decode(&hx("a10101 ff".replace(' ', "").as_str())), Err(Error::TrailingBytes));
}

#[test]
fn huge_declared_lengths_do_not_allocate() {
    // 2^63 element array declared with two bytes of input.
    assert_eq!(decode(&hx("9b80000000000000000000")), Err(Error::LengthExceedsInput));
    assert_eq!(decode(&hx("5bffffffffffffffff")), Err(Error::LengthExceedsInput));
}

#[test]
fn depth_is_bounded() {
    let ok: Vec<u8> = std::iter::repeat_n(0x81, MAX_DEPTH).chain([0x00]).collect();
    assert!(decode(&ok).is_ok());
    let too_deep: Vec<u8> = std::iter::repeat_n(0x81, MAX_DEPTH + 2).chain([0x00]).collect();
    assert_eq!(decode(&too_deep), Err(Error::TooDeep));
}

#[test]
fn signed_integer_conversion() {
    assert_eq!(Value::from(-1i64), Value::Nint(0));
    assert_eq!(Value::from(-500i64), Value::Nint(499));
    assert_eq!(Value::from(i64::MIN), Value::Nint(i64::MAX as u64));
    assert_eq!(Value::Nint(499).as_i64().unwrap(), -500);
    assert_eq!(Value::from(i64::MIN).as_i64().unwrap(), i64::MIN);
    assert_eq!(Value::Uint(u64::MAX).as_i64(), Err(Error::OutOfRange));
}

#[test]
fn fields_reject_unknown_and_missing() {
    let v = Value::Map(Map::new().with(1u8, "a").with(2u8, "b").with(9u8, "extra"));
    let mut f = Fields::new(&v).unwrap();
    assert_eq!(f.req(1).unwrap().as_text().unwrap(), "a");
    assert_eq!(f.req(2).unwrap().as_text().unwrap(), "b");
    assert!(matches!(f.finish(), Err(Error::UnknownField(_))));

    let v = Value::Map(Map::new().with(1u8, "a"));
    let mut f = Fields::new(&v).unwrap();
    assert!(f.req(1).is_ok());
    assert_eq!(f.req(2), Err(Error::MissingField(2)));
}

#[test]
fn optional_null_counts_as_absent_when_reading_fields() {
    let v = Value::Map(Map::new().with(1u8, Value::Null));
    let mut f = Fields::new(&v).unwrap();
    assert!(f.opt(1).is_none());
    assert!(f.finish().is_ok());
}

#[test]
fn diagnostic_notation() {
    let v = Value::Map(
        Map::new()
            .with(1u8, "hi")
            .with(2u8, vec![0xdeu8, 0xad])
            .with(3u8, Value::Array(vec![Value::Null, true.into(), (-5i64).into()])),
    );
    assert_eq!(v.diag(), r#"{1: "hi", 2: h'dead', 3: [null, true, -5]}"#);
}

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<u64>().prop_map(Value::Uint),
        any::<u64>().prop_map(Value::Nint),
        prop::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        ".{0,20}".prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::vec((inner.clone(), inner.clone()), 0..5).prop_map(|kv| {
                let mut m = Map::new();
                for (k, v) in kv {
                    let _ = m.insert(k, v); // duplicate keys are dropped
                }
                Value::Map(m)
            }),
            (any::<u64>(), inner).prop_map(|(t, v)| Value::Tag(t, Box::new(v))),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn roundtrip(v in arb_value()) {
        let bytes = encode(&v);
        let back = decode(&bytes).unwrap();
        prop_assert_eq!(&back, &v);
        prop_assert_eq!(encode(&back), bytes);
    }

    // The core canonicality property: any input the decoder accepts must be
    // reproduced byte-for-byte by the encoder, so no two byte strings decode
    // to the same value.
    #[test]
    fn accepted_input_is_canonical(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(v) = decode(&bytes) {
            prop_assert_eq!(encode(&v), bytes);
        }
    }

    #[test]
    fn decoder_never_panics_on_mutations(v in arb_value(), idx in any::<prop::sample::Index>(), flip in 1u8..=255) {
        let mut bytes = encode(&v);
        if !bytes.is_empty() {
            let i = idx.index(bytes.len());
            bytes[i] ^= flip;
        }
        let _ = decode(&bytes);
    }
}

mod record_tests {
    use super::*;

    crate::record! {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct Sample {
            1 => name: String,
            2 => size: u64,
            3 => note: Option<String>,
            4 => tags: Vec<String>,
            5 => id: [u8; 4],
            6 => blob: Vec<u8>,
        }
    }

    fn sample() -> Sample {
        Sample {
            name: "n".into(),
            size: 300,
            note: None,
            tags: vec!["a".into(), "b".into()],
            id: [1, 2, 3, 4],
            blob: vec![9, 9],
        }
    }

    #[test]
    fn record_roundtrip_omits_none() {
        let s = sample();
        let bytes = s.to_cbor();
        assert!(!s.to_value().as_map().unwrap().iter().any(|(k, _)| k == &Value::Uint(3)));
        assert_eq!(Sample::from_cbor(&bytes).unwrap(), s);
        let with_note = Sample { note: Some("x".into()), ..sample() };
        assert_eq!(Sample::from_cbor(&with_note.to_cbor()).unwrap(), with_note);
    }

    #[test]
    fn record_rejects_unknown_missing_and_explicit_null() {
        let mut m = sample().to_value().as_map().unwrap().clone();
        m.insert(99u8, 1u8).unwrap();
        assert!(matches!(Sample::from_value(&Value::Map(m)), Err(Error::UnknownField(_))));

        let mut m = Map::new();
        m.insert(1u8, "n").unwrap();
        assert_eq!(Sample::from_value(&Value::Map(m)), Err(Error::MissingField(2)));

        // Explicit null for an optional field parses but is not canonical.
        let mut m = sample().to_value().as_map().unwrap().clone();
        m.insert(3u8, Value::Null).unwrap();
        let bytes = encode(&Value::Map(m));
        assert_eq!(Sample::from_cbor(&bytes), Err(Error::Invalid("record is not in canonical form")));
    }

    #[test]
    fn record_type_mismatches_are_errors() {
        let mut m = sample().to_value().as_map().unwrap().clone();
        m.insert(2u8, "not a number").unwrap_err(); // duplicate key
        let v = Value::Map(
            Map::new()
                .with(1u8, "n")
                .with(2u8, "oops")
                .with(4u8, Value::Array(vec![]))
                .with(5u8, vec![1u8, 2, 3, 4])
                .with(6u8, vec![0u8]),
        );
        assert!(matches!(Sample::from_value(&v), Err(Error::Type { .. })));
        let v = Value::Map(
            Map::new()
                .with(1u8, "n")
                .with(2u8, 1u8)
                .with(4u8, Value::Array(vec![]))
                .with(5u8, vec![1u8, 2, 3])
                .with(6u8, vec![0u8]),
        );
        assert!(Sample::from_value(&v).is_err()); // wrong fixed length
    }
}
