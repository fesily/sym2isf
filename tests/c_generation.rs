//! The C generator's own contract: which documents it refuses, and where the
//! refusal is attributed. These cases need no compiler; the translation unit
//! itself is exercised against a real TCC in `tests/native_frontends.rs`.

use std::collections::BTreeMap;

use sym2isf::isf::IsfDocument;
use sym2isf::{BaseKind, BaseType, CompositeKind, Endian, Field, Target, TypeRef, UserType};

fn target() -> Target {
    Target {
        architecture: "x86_64".to_string(),
        pointer_size: 8,
        endian: Endian::Little,
    }
}

fn base(kind: BaseKind, size: u64, signed: bool) -> BaseType {
    BaseType {
        kind,
        size,
        signed,
        endian: Endian::Little,
        alignment: None,
        unsupported_reason: None,
    }
}

fn empty_document() -> IsfDocument {
    let mut document = IsfDocument::empty(target(), None);
    document
        .base_types
        .insert("void".to_string(), base(BaseKind::Void, 0, false));
    document
}

fn reference(name: &str) -> TypeRef {
    TypeRef::Base {
        name: name.to_string(),
        qualifiers: Vec::new(),
    }
}

fn field(offset: u64, ty: TypeRef) -> Field {
    Field {
        offset,
        ty,
        anonymous: None,
    }
}

fn user(kind: CompositeKind, size: u64, fields: Vec<(&str, Field)>) -> UserType {
    UserType {
        kind,
        size,
        fields: fields
            .into_iter()
            .map(|(name, member)| (name.to_string(), member))
            .collect(),
        alignment: None,
        incomplete: None,
        unsupported_reason: None,
    }
}

fn c_error(document: &IsfDocument, roots: &[&str]) -> String {
    let error = sym2isf::c::generate(document, &sym2isf::c::Request::types(roots))
        .expect_err("generation must fail");
    assert_eq!(error.kind(), "CGeneration", "{error:?}");
    error.to_string()
}

#[test]
fn roots_are_required_and_must_resolve_to_one_table() {
    let mut document = empty_document();
    document
        .base_types
        .insert("int32_t".to_string(), base(BaseKind::Int, 4, true));

    let message = c_error(&document, &[]);
    assert!(
        message.contains("cannot generate C for root types"),
        "{message}"
    );
    assert!(
        message.contains("at least one root type or function is required"),
        "{message}"
    );

    let message = c_error(&document, &["Missing"]);
    assert!(
        message.contains("cannot generate C for root type `Missing`"),
        "{message}"
    );
    assert!(message.contains("type not found"), "{message}");

    // A name owned by two tables has no default winner.
    document
        .typedefs
        .insert("int32_t".to_string(), reference("int32_t"));
    let message = c_error(&document, &["int32_t"]);
    assert!(message.contains("root type `int32_t`"), "{message}");
    assert!(
        message.contains("name matches more than one type table"),
        "{message}"
    );
}

#[test]
fn overlapping_members_are_refused_with_the_record() {
    let mut document = empty_document();
    document
        .base_types
        .insert("int32_t".to_string(), base(BaseKind::Int, 4, true));
    document.user_types.insert(
        "Overlap".to_string(),
        user(
            CompositeKind::Struct,
            8,
            vec![
                ("first", field(0, reference("int32_t"))),
                ("second", field(2, reference("int32_t"))),
            ],
        ),
    );
    let message = c_error(&document, &["Overlap"]);
    assert!(message.contains("type `Overlap`"), "{message}");
    assert!(message.contains("overlap"), "{message}");
    assert!(message.contains("`first`"), "{message}");
    assert!(message.contains("`second`"), "{message}");
}

#[test]
fn pointer_width_overrides_are_refused() {
    let mut document = empty_document();
    document
        .base_types
        .insert("int32_t".to_string(), base(BaseKind::Int, 4, true));
    document.user_types.insert(
        "Holder".to_string(),
        user(
            CompositeKind::Struct,
            12,
            vec![(
                "short_pointer",
                field(
                    0,
                    TypeRef::Pointer {
                        subtype: Box::new(reference("int32_t")),
                        size: Some(4),
                        qualifiers: Vec::new(),
                        reference_kind: None,
                    },
                ),
            )],
        ),
    );
    let message = c_error(&document, &["Holder"]);
    assert!(
        message.contains("type `Holder`, field `short_pointer`"),
        "{message}"
    );
    assert!(message.contains("pointer of 4 bytes"), "{message}");
}

#[test]
fn complete_zero_sized_aggregates_are_refused() {
    let mut document = empty_document();
    document.user_types.insert(
        "Empty".to_string(),
        user(CompositeKind::Struct, 0, Vec::new()),
    );
    let message = c_error(&document, &["Empty"]);
    assert!(message.contains("root type `Empty`"), "{message}");
    assert!(message.contains("has size 0"), "{message}");

    // An incomplete aggregate is only declared, so it stays usable.
    let mut declared = empty_document();
    let mut empty = user(CompositeKind::Struct, 0, Vec::new());
    empty.incomplete = Some(true);
    declared.user_types.insert("Declared".to_string(), empty);
    let source = sym2isf::c::generate(&declared, &sym2isf::c::Request::types(&["Declared"]))
        .expect("declaration only");
    assert!(source.contains("s2c_s_Declared"), "{source}");
    assert!(!source.contains("sizeof(s2c_s_Declared)"), "{source}");
}

#[test]
fn unsupported_scalar_widths_are_refused() {
    let mut document = empty_document();
    document
        .base_types
        .insert("odd_width".to_string(), base(BaseKind::Int, 3, false));
    document
        .base_types
        .insert("wide_float".to_string(), base(BaseKind::Float, 16, true));
    document.user_types.insert(
        "Wide".to_string(),
        user(
            CompositeKind::Struct,
            19,
            vec![
                ("odd", field(0, reference("odd_width"))),
                ("wide", field(3, reference("wide_float"))),
            ],
        ),
    );
    let message = c_error(&document, &["Wide"]);
    assert!(message.contains("type `odd_width`"), "{message}");
    assert!(message.contains("scalar width 3 bytes"), "{message}");

    let mut floating = empty_document();
    floating
        .base_types
        .insert("wide_float".to_string(), base(BaseKind::Float, 16, true));
    floating.user_types.insert(
        "Holder".to_string(),
        user(
            CompositeKind::Struct,
            16,
            vec![("wide", field(0, reference("wide_float")))],
        ),
    );
    let message = c_error(&floating, &["Holder"]);
    assert!(message.contains("type `wide_float`"), "{message}");
    assert!(
        message.contains("floating point width 16 bytes"),
        "{message}"
    );
}

#[test]
fn invalid_parameter_lists_and_restrict_are_refused() {
    let mut document = empty_document();
    document
        .base_types
        .insert("int32_t".to_string(), base(BaseKind::Int, 4, true));
    document.user_types.insert(
        "VoidParams".to_string(),
        user(
            CompositeKind::Struct,
            8,
            vec![(
                "cb",
                field(
                    0,
                    TypeRef::Pointer {
                        subtype: Box::new(TypeRef::Function {
                            return_type: Box::new(reference("void")),
                            parameters: vec![
                                sym2isf::Parameter {
                                    name: None,
                                    ty: reference("void"),
                                },
                                sym2isf::Parameter {
                                    name: None,
                                    ty: reference("int32_t"),
                                },
                            ],
                            variadic: None,
                            calling_convention: None,
                            qualifiers: Vec::new(),
                        }),
                        size: None,
                        qualifiers: Vec::new(),
                        reference_kind: None,
                    },
                ),
            )],
        ),
    );
    let message = c_error(&document, &["VoidParams"]);
    assert!(
        message.contains("type `VoidParams`, field `cb`"),
        "{message}"
    );
    assert!(
        message.contains("void is only valid as the sole parameter"),
        "{message}"
    );

    // `f(void)` alone stays legal and names an empty list.
    let mut sole_void = empty_document();
    sole_void.user_types.insert(
        "SoleVoid".to_string(),
        user(
            CompositeKind::Struct,
            8,
            vec![(
                "cb",
                field(
                    0,
                    TypeRef::Pointer {
                        subtype: Box::new(TypeRef::Function {
                            return_type: Box::new(reference("void")),
                            parameters: vec![sym2isf::Parameter {
                                name: None,
                                ty: reference("void"),
                            }],
                            variadic: None,
                            calling_convention: None,
                            qualifiers: Vec::new(),
                        }),
                        size: None,
                        qualifiers: Vec::new(),
                        reference_kind: None,
                    },
                ),
            )],
        ),
    );
    sym2isf::c::generate(&sole_void, &sym2isf::c::Request::types(&["SoleVoid"]))
        .expect("a lone void parameter is a prototype");

    // A typedef hides nothing: `restrict` on a function pointer is still invalid.
    let mut restricted = empty_document();
    restricted.typedefs.insert(
        "fp_t".to_string(),
        TypeRef::Pointer {
            subtype: Box::new(TypeRef::Function {
                return_type: Box::new(reference("void")),
                parameters: Vec::new(),
                variadic: None,
                calling_convention: None,
                qualifiers: Vec::new(),
            }),
            size: None,
            qualifiers: Vec::new(),
            reference_kind: None,
        },
    );
    restricted.user_types.insert(
        "Holder".to_string(),
        user(
            CompositeKind::Struct,
            8,
            vec![(
                "cb",
                field(
                    0,
                    TypeRef::Typedef {
                        name: "fp_t".to_string(),
                        qualifiers: vec![sym2isf::Qualifier::Restrict],
                    },
                ),
            )],
        ),
    );
    let message = c_error(&restricted, &["Holder"]);
    assert!(message.contains("type `Holder`, field `cb`"), "{message}");
    assert!(
        message.contains("restrict needs an object pointer"),
        "{message}"
    );
}

#[test]
fn extreme_but_valid_records_are_reported_not_overflowed() {
    // A fixed-width C type exists only for 1/2/4/8 bytes; the width is rejected
    // before any bit arithmetic can overflow.
    let mut document = empty_document();
    document
        .base_types
        .insert("huge".to_string(), base(BaseKind::Int, 1 << 61, true));
    document.user_types.insert(
        "Huge".to_string(),
        user(
            CompositeKind::Struct,
            1 << 61,
            vec![("value", field(0, reference("huge")))],
        ),
    );
    let message = c_error(&document, &["Huge"]);
    assert!(message.contains("type `huge`"), "{message}");
    assert!(
        message.contains(&format!(
            "scalar width {} bytes has no fixed-width C type",
            1u64 << 61
        )),
        "{message}"
    );

    // A bit-field that sits at an offset near `u64::MAX / 8` still yields a unit:
    // the accessor addresses bytes, so no absolute bit address is formed.
    let mut extreme = empty_document();
    extreme
        .base_types
        .insert("__isf_bitsu8".to_string(), base(BaseKind::Int, 1, false));
    extreme.user_types.insert(
        "HugeBits".to_string(),
        user(
            CompositeKind::Struct,
            (1 << 61) + 1,
            vec![(
                "far",
                Field {
                    offset: 1 << 61,
                    ty: TypeRef::Bitfield {
                        bit_length: 1,
                        bit_position: 0,
                        ty: Box::new(reference("__isf_bitsu8")),
                        declared_type: Some(Box::new(reference("__isf_bitsu8"))),
                    },
                    anonymous: None,
                },
            )],
        ),
    );
    let source = sym2isf::c::generate(&extreme, &sym2isf::c::Request::types(&["HugeBits"]))
        .expect("a far but valid offset is not an overflow");
    assert!(
        source.contains("s2c_s_HugeBits"),
        "the aggregate is emitted"
    );
}

#[test]
fn big_endian_documents_are_refused() {
    let mut document = empty_document();
    document.metadata.sym2isf.target.endian = Endian::Big;
    let message = c_error(&document, &["void"]);
    assert!(message.contains("root types"), "{message}");
    assert!(message.contains("little-endian"), "{message}");
}

#[test]
fn output_is_a_pure_function_of_the_document() {
    let mut document = empty_document();
    document
        .base_types
        .insert("int32_t".to_string(), base(BaseKind::Int, 4, true));
    document.user_types.insert(
        "A".to_string(),
        user(
            CompositeKind::Struct,
            4,
            vec![("value", field(0, reference("int32_t")))],
        ),
    );
    document.user_types.insert(
        "B".to_string(),
        user(
            CompositeKind::Struct,
            4,
            vec![("other", field(0, reference("int32_t")))],
        ),
    );
    let forward =
        sym2isf::c::generate(&document, &sym2isf::c::Request::types(&["A", "B"])).expect("roots");
    let reversed = sym2isf::c::generate(&document, &sym2isf::c::Request::types(&["B", "A", "A"]))
        .expect("roots");
    assert_eq!(forward, reversed, "root order and duplicates do not matter");
    assert!(forward.ends_with('\n'), "the unit ends with a newline");
    assert!(
        !forward.contains("main("),
        "the unit declares no entry point"
    );
    let _ = BTreeMap::<u8, u8>::new();
}
