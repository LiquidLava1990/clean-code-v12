//! Integration tests for the public `cc-cpg` schema surface.
//!
//! Covers the test matrix listed in the planning doc:
//! - `node_serde_roundtrip`
//! - `edge_serde_roundtrip`
//! - `schema_version_constant`
//! - `node_id_newtype_safety`
//! - `value_variants_complete`
//! - `position_one_indexed`

use std::collections::BTreeMap;

use cc_cpg::{
    CpgWriteBatch, Edge, EdgeId, EdgeKind, Node, NodeBuilder, NodeId, NodeKind, Position, Range,
    Sha256, Value, SCHEMA_VERSION,
};

const fn bincode_cfg() -> bincode::config::Configuration {
    bincode::config::standard()
}

fn bincode_round_trip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let bytes = bincode::serde::encode_to_vec(value, bincode_cfg()).expect("encode");
    let (decoded, _len): (T, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode_cfg()).expect("decode");
    decoded
}

fn json_round_trip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let s = serde_json::to_string(value).expect("encode json");
    serde_json::from_str(&s).expect("decode json")
}

fn sample_node(id: NodeId, kind: NodeKind) -> Node {
    let mut props = BTreeMap::new();
    props.insert("name".into(), Value::String(format!("{kind:?}_sample")));
    props.insert("count".into(), Value::Int(42));
    Node::new(id, kind, props)
}

#[test]
fn schema_version_constant() {
    // Locked at 1 for Phase 1. Bumping requires a coordinated cache flush.
    assert_eq!(SCHEMA_VERSION, 1);
}

#[test]
fn node_serde_roundtrip() {
    for (idx, kind) in NodeKind::all().iter().copied().enumerate() {
        let node = sample_node(NodeId::new(idx as u64 + 1), kind);

        let via_bincode = bincode_round_trip(&node);
        assert_eq!(via_bincode, node, "bincode lost data for {kind:?}");

        let via_json = json_round_trip(&node);
        assert_eq!(via_json, node, "json lost data for {kind:?}");
    }
    // Confirm the variant count matches the schema doc.
    assert_eq!(NodeKind::all().len(), 24);
}

#[test]
fn edge_serde_roundtrip() {
    for (idx, kind) in EdgeKind::all().iter().copied().enumerate() {
        let edge = Edge::new(
            EdgeId::new(idx as u64 + 1),
            kind,
            NodeId::new(1),
            NodeId::new(2),
        );

        let via_bincode = bincode_round_trip(&edge);
        assert_eq!(via_bincode, edge, "bincode lost data for {kind:?}");

        let via_json = json_round_trip(&edge);
        assert_eq!(via_json, edge, "json lost data for {kind:?}");
    }
    assert_eq!(EdgeKind::all().len(), 12);
}

#[test]
fn node_id_newtype_safety() {
    // Compile-time guarantee: there is no `From<u64> for NodeId`. The only
    // way to get a NodeId from a raw u64 is the explicit `NodeId::new`.
    let id = NodeId::new(7);
    assert_eq!(id.get(), 7);

    // Sanity: NodeId is ordered, hashable, and copy.
    let mut set = std::collections::HashSet::new();
    set.insert(id);
    assert!(set.contains(&NodeId::new(7)));
}

#[test]
fn value_variants_complete() {
    let mut nested = BTreeMap::new();
    nested.insert("k".to_string(), Value::Bool(true));

    let variants: [Value; 13] = [
        Value::Null,
        Value::Bool(true),
        Value::Int(-7),
        Value::Uint(8),
        Value::Float(3.5),
        Value::String("hello".into()),
        Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
        Value::NodeRef(NodeId::new(11)),
        Value::NodeList(vec![NodeId::new(1), NodeId::new(2)]),
        Value::Position(Position::new(2, 3, 17)),
        Value::Range(Range::new(
            Position::start_of_file(),
            Position::new(2, 1, 16),
        )),
        Value::Hash(Sha256::of(b"abc")),
        Value::Map(nested),
    ];

    let expected_tags = [
        "null",
        "bool",
        "int",
        "uint",
        "float",
        "string",
        "bytes",
        "node_ref",
        "node_list",
        "position",
        "range",
        "hash",
        "map",
    ];

    for (value, expected) in variants.iter().zip(expected_tags) {
        assert_eq!(value.tag(), expected);
        let via_bincode = bincode_round_trip(value);
        assert_eq!(via_bincode, *value, "bincode lost {expected}");
        let via_json = json_round_trip(value);
        assert_eq!(via_json, *value, "json lost {expected}");
    }
}

#[test]
fn position_one_indexed() {
    let start = Position::start_of_file();
    assert_eq!(start.line, 1);
    assert_eq!(start.column, 1);
    assert_eq!(start.offset, 0);

    let r = Range::new(start, Position::new(1, 5, 4));
    assert_eq!(r.byte_len(), 4);
}

#[test]
fn sha256_hex_round_trip() {
    let digest = Sha256::of(b"clean code v12");
    let hex = digest.to_hex();
    assert_eq!(hex.len(), 64);
    let parsed: Sha256 = hex.parse().expect("parse hex");
    assert_eq!(parsed, digest);

    // Display matches to_hex.
    assert_eq!(format!("{digest}"), hex);

    // Bad input rejected with actionable error.
    let err = "not-hex".parse::<Sha256>().unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("64 hex characters"), "msg was: {msg}");
}

#[test]
fn batch_allocates_dense_ids_and_rejects_dangling_edges() {
    let mut batch = CpgWriteBatch::new();
    let a = batch.push_node(NodeBuilder::new(NodeKind::File));
    let b = batch.push_node(NodeBuilder::new(NodeKind::Module));
    assert_eq!(a, NodeId::new(1));
    assert_eq!(b, NodeId::new(2));

    let edge_id = batch
        .push_edge(EdgeKind::AST_PARENT, b, a)
        .expect("valid edge");
    assert_eq!(edge_id, EdgeId::new(1));

    let dangling = batch.push_edge(EdgeKind::CFG_NEXT, a, NodeId::new(999));
    assert!(matches!(
        dangling,
        Err(cc_cpg::CpgError::DanglingEdge { .. })
    ));
}

#[test]
fn batch_round_trip_bincode() {
    let mut batch = CpgWriteBatch::new();
    let f = batch.push_node(
        NodeBuilder::new(NodeKind::File)
            .with_prop("path", Value::String("a.py".into()))
            .with_prop("language", Value::String("python".into())),
    );
    let m = batch.push_node(NodeBuilder::new(NodeKind::Module));
    batch.push_edge(EdgeKind::AST_PARENT, m, f).unwrap();

    let decoded: CpgWriteBatch = bincode_round_trip(&batch);
    assert_eq!(decoded.nodes().len(), 2);
    assert_eq!(decoded.edges().len(), 1);
}
