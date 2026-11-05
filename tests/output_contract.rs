//! Consumer-visible output contract: what a document may contain, what the
//! writer produces, and which failures are part of the interface.
//!
//! These cases need no compiler: they exercise the normalization/emission layer
//! and the writer. Compiler-generated input is covered by
//! `tests/native_frontends.rs`.

use std::collections::BTreeMap;
use std::process::{Command, Stdio};

use serde_json::Value;
use sym2isf::isf::{IntValue, IsfDocument, Metadata};
use sym2isf::normalize::{CompositeRecord, GlobalSymbol, Member, Node, TypeGraph, TypedefRecord};
use sym2isf::{
    BaseKind, BaseName, BaseRecord, CompositeKind, Endian, Error, Origin, Symbol, Target, TypeRef,
};

fn target() -> Target {
    Target {
        architecture: "x86_64".to_string(),
        pointer_size: 8,
        endian: Endian::Little,
    }
}

fn int32(graph: &mut TypeGraph) -> sym2isf::TypeId {
    graph.base(BaseRecord {
        name: BaseName::Source("int32_t".to_string()),
        size: 4,
        signed: true,
        kind: BaseKind::Int,
        alignment: Some(4),
        unsupported_reason: None,
        origin: Origin::Synthetic {
            tag: "int32".to_string(),
        },
    })
}

fn uint8(graph: &mut TypeGraph) -> sym2isf::TypeId {
    graph.base(BaseRecord {
        name: BaseName::Source("uint8_t".to_string()),
        size: 1,
        signed: false,
        kind: BaseKind::Int,
        alignment: Some(1),
        unsupported_reason: None,
        origin: Origin::Synthetic {
            tag: "uint8".to_string(),
        },
    })
}

fn dwarf_origin(offset: u64) -> Origin {
    Origin::Dwarf {
        section: ".debug_info".to_string(),
        offset,
    }
}

/// A document with a self-referential aggregate and a 0-address symbol.
fn node_document() -> IsfDocument {
    let mut graph = TypeGraph::new(target());
    let int32 = int32(&mut graph);
    let node = graph.composite_slot();
    let next = graph.pointer_to(node, None);
    define(
        graph.composite_mut(node).unwrap(),
        Some(16),
        None,
        vec![
            Member {
                name: Some("value".to_string()),
                offset: 0,
                ty: int32,
                bitfield: None,
                anonymous: false,
            },
            Member {
                name: Some("next".to_string()),
                offset: 8,
                ty: next,
                bitfield: None,
                anonymous: false,
            },
        ],
        dwarf_origin(0x100),
    );
    graph.composite_mut(node).unwrap().name = Some("Node".to_string());

    let global = graph.pointer_to(node, None);
    let mut symbols = BTreeMap::new();
    symbols.insert(
        "head".to_string(),
        GlobalSymbol {
            address: Some(0),
            ty: Some(global),
        },
    );
    graph.emit(None, symbols, BTreeMap::new()).unwrap()
}

fn define(
    record: &mut CompositeRecord,
    size: Option<u64>,
    alignment: Option<u64>,
    members: Vec<Member>,
    origin: Origin,
) {
    record.size = size;
    record.alignment = alignment;
    record.members = members;
    record.origin = origin;
}

fn empty_document() -> IsfDocument {
    let mut document = IsfDocument::empty(target(), None);
    document.base_types.insert(
        "void".to_string(),
        sym2isf::BaseType {
            kind: BaseKind::Void,
            size: 0,
            signed: false,
            endian: Endian::Little,
            alignment: None,
            unsupported_reason: None,
        },
    );
    document
}

#[test]
fn self_referential_pointer_forms_a_named_cycle() {
    let document = node_document();
    document.validate().expect("valid document");

    let node = &document.user_types["Node"];
    assert_eq!(node.size, 16);
    assert_eq!(node.kind, CompositeKind::Struct);
    let next = &node.fields["next"];
    assert_eq!(next.offset, 8);
    match &next.ty {
        TypeRef::Pointer { subtype, .. } => match &**subtype {
            TypeRef::Struct { name, .. } => assert_eq!(name, "Node"),
            other => panic!("unexpected pointee {other:?}"),
        },
        other => panic!("unexpected field type {other:?}"),
    }

    // The symbol address zero is a real address, not missing information.
    assert_eq!(document.symbols["head"].address, Some(0));
    let json = document.to_vec().unwrap();
    let value: Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(value["symbols"]["head"]["address"], Value::from(0));
}

#[test]
fn tables_are_present_and_metadata_is_fixed() {
    let document = empty_document();
    let json = document.to_vec().expect("serialized");
    let value: Value = serde_json::from_slice(&json).unwrap();
    for table in [
        "metadata",
        "base_types",
        "user_types",
        "enums",
        "typedefs",
        "symbols",
        "functions",
    ] {
        assert!(value.get(table).is_some(), "missing table {table}");
        if table != "metadata" {
            assert!(value[table].is_object(), "{table} must be an object");
        }
    }
    // Table order is part of the contract; `Value` sorts keys, so check the text.
    let text = std::str::from_utf8(&json).unwrap();
    let mut last = 0usize;
    for table in [
        "\"metadata\"",
        "\"base_types\"",
        "\"user_types\"",
        "\"enums\"",
        "\"typedefs\"",
        "\"symbols\"",
        "\"functions\"",
    ] {
        let position = text.find(table).expect("table present");
        assert!(position >= last, "table {table} is out of order");
        last = position;
    }
    assert_eq!(value["metadata"]["format"], "6.2.0");
    assert_eq!(value["metadata"]["producer"]["name"], "sym2isf");
    assert_eq!(
        value["metadata"]["producer"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(value["metadata"]["sym2isf"]["version"], 1);
    assert_eq!(
        value["metadata"]["sym2isf"]["target"]["architecture"],
        "x86_64"
    );
    assert_eq!(value["metadata"]["sym2isf"]["target"]["pointer_size"], 8);
    assert_eq!(value["metadata"]["sym2isf"]["target"]["endian"], "little");
    assert!(json.ends_with(b"\n"));
}

#[test]
fn alias_cycle_is_rejected() {
    let mut document = empty_document();
    document.typedefs.insert(
        "a_t".to_string(),
        TypeRef::Typedef {
            name: "b_t".to_string(),
            qualifiers: Vec::new(),
        },
    );
    document.typedefs.insert(
        "b_t".to_string(),
        TypeRef::Typedef {
            name: "a_t".to_string(),
            qualifiers: Vec::new(),
        },
    );
    let error = document.validate().expect_err("alias cycle");
    assert!(matches!(error, Error::InvalidDocument(_)), "{error:?}");
    assert!(
        error.to_string().contains("alias cycle"),
        "unexpected message: {error}"
    );
}

#[test]
fn recursive_alias_through_pointer_is_allowed() {
    let mut document = empty_document();
    document.typedefs.insert(
        "p_t".to_string(),
        TypeRef::Pointer {
            subtype: Box::new(TypeRef::Typedef {
                name: "p_t".to_string(),
                qualifiers: Vec::new(),
            }),
            size: None,
            qualifiers: Vec::new(),
            reference_kind: None,
        },
    );
    document.validate().expect("pointer recursion is fine");
}

#[test]
fn by_value_recursion_is_rejected() {
    let mut document = empty_document();
    document.user_types.insert(
        "S".to_string(),
        sym2isf::UserType {
            kind: CompositeKind::Struct,
            size: 8,
            fields: BTreeMap::from([(
                "inner".to_string(),
                sym2isf::Field {
                    offset: 0,
                    ty: TypeRef::Struct {
                        name: "S".to_string(),
                        qualifiers: Vec::new(),
                    },
                    anonymous: None,
                },
            )]),
            alignment: None,
            incomplete: None,
            unsupported_reason: None,
        },
    );
    let error = document.validate().expect_err("by-value recursion");
    assert!(
        error.to_string().contains("recursive by-value containment"),
        "unexpected message: {error}"
    );
}

#[test]
fn dangling_reference_is_rejected() {
    let mut document = empty_document();
    document.symbols.insert(
        "orphan".to_string(),
        Symbol {
            address: Some(4096),
            ty: Some(TypeRef::Struct {
                name: "Missing".to_string(),
                qualifiers: Vec::new(),
            }),
        },
    );
    let error = document.validate().expect_err("dangling reference");
    assert!(
        error
            .to_string()
            .contains("dangling reference to missing struct"),
        "unexpected message: {error}"
    );
}

#[test]
fn overflowing_array_span_is_rejected() {
    let mut document = empty_document();
    let mut graph = TypeGraph::new(target());
    let int32 = int32(&mut graph);
    let array = graph.array_of(int32, u64::MAX);
    let composite = graph.composite_slot();
    define(
        graph.composite_mut(composite).unwrap(),
        Some(8),
        None,
        vec![Member {
            name: Some("huge".to_string()),
            offset: 0,
            ty: array,
            bitfield: None,
            anonymous: false,
        }],
        dwarf_origin(0x200),
    );
    graph.composite_mut(composite).unwrap().name = Some("Huge".to_string());
    let emitted = graph.emit(None, BTreeMap::new(), BTreeMap::new());
    // The span overflows before anything is written.
    let error = match emitted {
        Ok(emitted) => emitted.validate().expect_err("overflow"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("overflow") || error.to_string().contains("overflows"),
        "unexpected message: {error}"
    );
    // Guard the manual document path too.
    document.user_types.insert(
        "Other".to_string(),
        sym2isf::UserType {
            kind: CompositeKind::Struct,
            size: 8,
            fields: BTreeMap::from([(
                "huge".to_string(),
                sym2isf::Field {
                    offset: 0,
                    ty: TypeRef::Array {
                        count: u64::MAX,
                        subtype: Box::new(TypeRef::Base {
                            name: "void".to_string(),
                            qualifiers: Vec::new(),
                        }),
                        qualifiers: Vec::new(),
                    },
                    anonymous: None,
                },
            )]),
            alignment: None,
            incomplete: None,
            unsupported_reason: None,
        },
    );
    assert!(document.validate().is_err());
}

#[test]
fn incomplete_declaration_differs_from_a_zero_address() {
    let mut document = empty_document();
    document.user_types.insert(
        "Fwd".to_string(),
        sym2isf::UserType {
            kind: CompositeKind::Struct,
            size: 0,
            fields: BTreeMap::new(),
            alignment: None,
            incomplete: Some(true),
            unsupported_reason: None,
        },
    );
    // Using the forward declaration by value is an error.
    let mut by_value = document.clone();
    by_value.user_types.insert(
        "Holder".to_string(),
        sym2isf::UserType {
            kind: CompositeKind::Struct,
            size: 8,
            fields: BTreeMap::from([(
                "fwd".to_string(),
                sym2isf::Field {
                    offset: 0,
                    ty: TypeRef::Struct {
                        name: "Fwd".to_string(),
                        qualifiers: Vec::new(),
                    },
                    anonymous: None,
                },
            )]),
            alignment: None,
            incomplete: None,
            unsupported_reason: None,
        },
    );
    let error = by_value.validate().expect_err("incomplete by value");
    assert!(
        error
            .to_string()
            .contains("incomplete aggregate used by value"),
        "unexpected message: {error}"
    );

    // Behind a pointer it is fine, and the flag survives serialization.
    document.symbols.insert(
        "fwd_ptr".to_string(),
        Symbol {
            address: Some(0),
            ty: Some(TypeRef::Pointer {
                subtype: Box::new(TypeRef::Struct {
                    name: "Fwd".to_string(),
                    qualifiers: Vec::new(),
                }),
                size: None,
                qualifiers: Vec::new(),
                reference_kind: None,
            }),
        },
    );
    document.validate().expect("pointer to forward declaration");
    let json = document.to_vec().unwrap();
    let value: Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(value["user_types"]["Fwd"]["incomplete"], Value::Bool(true));
    assert_eq!(value["symbols"]["fwd_ptr"]["address"], Value::from(0));
    let decoded: IsfDocument = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, document);
}

#[test]
fn addresses_above_two_to_the_53_stay_exact() {
    let address = 0x0020_0000_0000_0001_u64;
    assert!(address > (1u64 << 53));
    let mut document = empty_document();
    document.symbols.insert(
        "high".to_string(),
        Symbol {
            address: Some(address),
            ty: None,
        },
    );
    let json = document.to_vec().unwrap();
    let text = std::str::from_utf8(&json).unwrap();
    assert!(
        text.contains(&address.to_string()),
        "address must be written as an exact decimal integer"
    );
    let value: Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(value["symbols"]["high"]["address"].as_u64(), Some(address));
    let decoded: IsfDocument = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded.symbols["high"].address, Some(address));
}

#[test]
fn enum_constants_keep_full_width() {
    let mut document = empty_document();
    document.base_types.insert(
        "uint64_t".to_string(),
        sym2isf::BaseType {
            kind: BaseKind::Int,
            size: 8,
            signed: false,
            endian: Endian::Little,
            alignment: Some(8),
            unsupported_reason: None,
        },
    );
    document.enums.insert(
        "Wide".to_string(),
        sym2isf::EnumType {
            size: 8,
            base: Some("uint64_t".to_string()),
            constants: BTreeMap::from([
                ("MAX".to_string(), IntValue::Unsigned(u64::MAX)),
                ("NEG".to_string(), IntValue::Signed(-3)),
            ]),
        },
    );
    // `NEG` does not fit an unsigned base.
    assert!(document.validate().is_err());
    document
        .enums
        .get_mut("Wide")
        .unwrap()
        .constants
        .remove("NEG");
    document.validate().expect("unsigned constants fit");
    let json = document.to_vec().unwrap();
    let decoded: IsfDocument = serde_json::from_slice(&json).unwrap();
    assert_eq!(
        decoded.enums["Wide"].constants["MAX"],
        IntValue::Unsigned(u64::MAX)
    );
}

#[test]
fn deserialized_document_serializes_identically() {
    // The writer and the reader must agree exactly: a consumer that loads the
    // document and writes it back produces the same bytes.
    let document = node_document();
    let bytes = document.to_vec().unwrap();
    let decoded: IsfDocument = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, document);
    decoded.validate().expect("a produced document validates");
    assert_eq!(decoded.to_vec().unwrap(), bytes);
}

#[test]
fn metadata_carries_no_paths_or_timestamps() {
    // Only the producer, the format version and the target ABI may appear.
    let value: Value = serde_json::from_slice(&empty_document().to_vec().unwrap()).unwrap();
    let metadata = value["metadata"].as_object().expect("metadata");
    let mut keys: Vec<&str> = metadata.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["format", "producer", "sym2isf"]);
    let mut producer: Vec<&str> = metadata["producer"]
        .as_object()
        .expect("producer")
        .keys()
        .map(String::as_str)
        .collect();
    producer.sort_unstable();
    assert_eq!(producer, vec!["name", "version"]);
    let mut target: Vec<&str> = metadata["sym2isf"]["target"]
        .as_object()
        .expect("target")
        .keys()
        .map(String::as_str)
        .collect();
    target.sort_unstable();
    assert_eq!(target, vec!["architecture", "endian", "pointer_size"]);
    // Every string in the metadata is one of the fixed literals: no path, no
    // timestamp, no host name.
    fn strings(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::String(text) => out.push(text.clone()),
            Value::Array(items) => items.iter().for_each(|item| strings(item, out)),
            Value::Object(map) => map.values().for_each(|item| strings(item, out)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    strings(&value["metadata"], &mut found);
    found.sort();
    let expected = ["0.1.0", "6.2.0", "little", "sym2isf", "x86_64"];
    assert_eq!(
        found.iter().map(String::as_str).collect::<Vec<_>>(),
        expected,
        "metadata strings are fixed"
    );
}

#[test]
fn repeated_conversion_is_byte_identical() {
    let document = node_document();
    let first = document.to_vec().unwrap();
    let second = document.to_vec().unwrap();
    assert_eq!(first, second);
    let third = node_document().to_vec().unwrap();
    assert_eq!(first, third);
}

#[test]
fn xz_output_round_trips_to_the_same_document() {
    let directory = tempfile::tempdir().unwrap();
    let plain_path = directory.path().join("probe.json");
    let packed_path = directory.path().join("probe.json.xz");
    let document = node_document();
    document.save(&plain_path).unwrap();
    document.save(&packed_path).unwrap();

    let plain = std::fs::read(&plain_path).unwrap();
    let packed = std::fs::read(&packed_path).unwrap();
    assert_ne!(plain, packed, "xz payload must differ from plain json");
    let mut decoded = Vec::new();
    lzma_rs::xz_decompress(&mut std::io::Cursor::new(&packed), &mut decoded).unwrap();
    assert_eq!(decoded, plain);
    assert_eq!(plain, document.to_vec().unwrap());

    let from_plain: IsfDocument = serde_json::from_slice(&plain).unwrap();
    let from_packed: IsfDocument = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(from_plain, document);
    assert_eq!(from_packed, document);
}

#[test]
fn save_refuses_to_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("out.json");
    std::fs::write(&path, b"keep me").unwrap();
    let error = empty_document().save(&path).expect_err("existing output");
    assert!(matches!(error, Error::OutputExists { .. }), "{error:?}");
    assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
}

#[test]
fn save_rejects_unknown_suffix_and_missing_parent() {
    let directory = tempfile::tempdir().unwrap();
    let bad = directory.path().join("out.bin");
    let error = empty_document().save(&bad).expect_err("bad suffix");
    assert!(
        matches!(error, Error::UnsupportedOutput { .. }),
        "{error:?}"
    );
    assert!(!bad.exists());

    let missing = directory.path().join("no-such-dir/out.json");
    let error = empty_document().save(&missing).expect_err("missing parent");
    assert!(matches!(error, Error::Io { .. }), "{error:?}");
    assert!(!missing.exists());
}

#[test]
fn invalid_document_never_reaches_disk() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("out.json");
    let mut document = empty_document();
    document.symbols.insert(
        "orphan".to_string(),
        Symbol {
            address: None,
            ty: Some(TypeRef::Base {
                name: "no-such-base".to_string(),
                qualifiers: Vec::new(),
            }),
        },
    );
    let error = document.save(&path).expect_err("invalid");
    assert!(matches!(error, Error::InvalidDocument(_)), "{error:?}");
    assert!(
        !path.exists(),
        "nothing may be created for an invalid document"
    );
}

#[test]
fn metadata_type_is_reusable() {
    // The metadata is a plain data structure; consumers can round-trip it.
    let document = empty_document();
    let metadata: Metadata = document.metadata.clone();
    let json = serde_json::to_string(&metadata).unwrap();
    let decoded: Metadata = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, metadata);
}

#[test]
fn default_pointer_base_is_always_present() {
    let mut graph = TypeGraph::new(target());
    graph.void();
    graph.pointer_base();
    let document = graph.emit(None, BTreeMap::new(), BTreeMap::new()).unwrap();
    assert_eq!(document.base_types["void"].kind, BaseKind::Void);
    assert_eq!(document.base_types["void"].size, 0);
    assert_eq!(document.base_types["pointer"].kind, BaseKind::Pointer);
    assert_eq!(document.base_types["pointer"].size, 8);
    document.validate().unwrap();
}

#[test]
fn conflicting_definitions_are_suffixed_not_merged() {
    let mut graph = TypeGraph::new(target());
    let int32 = int32(&mut graph);
    let uint8 = uint8(&mut graph);

    let first = graph.composite_slot();
    graph.composite_mut(first).unwrap().name = Some("Clash".to_string());
    define(
        graph.composite_mut(first).unwrap(),
        Some(4),
        None,
        vec![Member {
            name: Some("a".to_string()),
            offset: 0,
            ty: int32,
            bitfield: None,
            anonymous: false,
        }],
        dwarf_origin(0x10),
    );

    let second = graph.composite_slot();
    graph.composite_mut(second).unwrap().name = Some("Clash".to_string());
    define(
        graph.composite_mut(second).unwrap(),
        Some(1),
        None,
        vec![Member {
            name: Some("b".to_string()),
            offset: 0,
            ty: uint8,
            bitfield: None,
            anonymous: false,
        }],
        dwarf_origin(0x20),
    );

    let document = graph.emit(None, BTreeMap::new(), BTreeMap::new()).unwrap();
    assert_eq!(
        document.user_types.len(),
        2,
        "{:?}",
        document.user_types.keys()
    );
    assert_eq!(document.user_types["Clash"].size, 4);
    assert_eq!(
        document.user_types["Clash__dwarf_debug_info_20"].size,
        1,
        "{:?}",
        document.user_types.keys().collect::<Vec<_>>()
    );
    document.validate().unwrap();
}

#[test]
fn equivalent_definitions_merge_under_one_name() {
    let mut graph = TypeGraph::new(target());
    let int32 = int32(&mut graph);
    for offset in [0x10u64, 0x40] {
        let id = graph.composite_slot();
        graph.composite_mut(id).unwrap().name = Some("Same".to_string());
        define(
            graph.composite_mut(id).unwrap(),
            Some(4),
            None,
            vec![Member {
                name: Some("a".to_string()),
                offset: 0,
                ty: int32,
                bitfield: None,
                anonymous: false,
            }],
            dwarf_origin(offset),
        );
    }
    let document = graph.emit(None, BTreeMap::new(), BTreeMap::new()).unwrap();
    assert_eq!(document.user_types.len(), 1);
    assert!(document.user_types.contains_key("Same"));
}

#[test]
fn anonymous_aggregates_get_source_derived_names() {
    let mut graph = TypeGraph::new(target());
    let int32 = int32(&mut graph);
    let anon = graph.composite_slot();
    define(
        graph.composite_mut(anon).unwrap(),
        Some(4),
        None,
        vec![Member {
            name: Some("value".to_string()),
            offset: 0,
            ty: int32,
            bitfield: None,
            anonymous: false,
        }],
        dwarf_origin(0x30),
    );
    let document = graph.emit(None, BTreeMap::new(), BTreeMap::new()).unwrap();
    assert!(
        document
            .user_types
            .contains_key("__anon_dwarf_debug_info_30"),
        "{:?}",
        document.user_types.keys().collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// CLI contract (no compiler needed)
// ---------------------------------------------------------------------------

fn cli() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sym2isf"));
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command
}

#[test]
fn cli_rejects_bad_arguments_with_exit_code_two() {
    let output = cli().arg("dwarf").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());

    let output = cli().arg("not-a-command").output().unwrap();
    assert_eq!(output.status.code(), Some(2));

    let output = cli()
        .args(["pdb", "x.pdb", "--output", "x.json", "--image-base", "zzz"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn cli_reports_missing_input() {
    let directory = tempfile::tempdir().unwrap();
    let out = directory.path().join("out.json");
    let output = cli()
        .args(["dwarf", "/nonexistent/sym2isf/probe"])
        .arg("--output")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Io"), "unexpected stderr: {stderr}");
    assert!(!out.exists());
}

#[test]
fn cli_reports_corrupt_input() {
    let directory = tempfile::tempdir().unwrap();
    let garbage = directory.path().join("garbage.bin");
    std::fs::write(&garbage, b"this is not an object file").unwrap();
    let out = directory.path().join("out.json");
    let output = cli()
        .arg("dwarf")
        .arg(&garbage)
        .arg("--output")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Corrupt") || stderr.contains("UnsupportedContainer"),
        "unexpected stderr: {stderr}"
    );
    assert!(!out.exists());
}

#[test]
fn cli_rejects_a_missing_required_output() {
    let output = cli().args(["dwarf", "probe"]).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn cli_reports_no_debug_information() {
    // A structurally valid ELF64 container without any section header table: it
    // parses, but carries no debug information.
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("empty-elf");
    std::fs::write(&image, minimal_elf64_without_sections()).unwrap();
    let out = directory.path().join("out.json");
    let output = cli()
        .arg("dwarf")
        .arg(&image)
        .arg("--output")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("NoDebugInfo"),
        "unexpected stderr: {stderr}"
    );
    assert!(!out.exists());
}

/// Minimal little-endian ELF64 header with no program headers and no sections.
fn minimal_elf64_without_sections() -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    bytes
}

#[test]
fn document_nodes_are_reachable_by_id() {
    let mut graph = TypeGraph::new(target());
    let int32 = int32(&mut graph);
    assert!(matches!(graph.node(int32), Node::Base(_)));
    let typedef = graph.push(Node::Typedef(TypedefRecord {
        name: "alias_t".to_string(),
        target: int32,
        domain: None,
        origin: Origin::Synthetic {
            tag: "alias".to_string(),
        },
    }));
    assert_eq!(graph.strip_wrappers(typedef), int32);
}
