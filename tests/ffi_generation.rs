//! Generation-time contract of the LuaJIT FFI product.
//!
//! These cases never run LuaJIT: they pin the selection errors, the gates that
//! keep an unverifiable declaration out of the module, and the determinism the
//! published bytes rely on. Behavioural evidence lives in
//! `native_frontends.rs`, where a real interpreter loads the module.

use std::collections::BTreeMap;

use sym2isf::c::{FfiRequest, generate_ffi};
use sym2isf::{
    BaseKind, BaseType, CompositeKind, Endian, EnumType, Field, Function, IntValue, IsfDocument,
    Parameter, Target, TypeRef, UserType,
};

// ---------------------------------------------------------------------------
// Document builders
// ---------------------------------------------------------------------------

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

fn function(
    address: Option<u64>,
    return_type: TypeRef,
    parameters: Vec<Parameter>,
    calling_convention: Option<&str>,
) -> Function {
    Function {
        address,
        return_type,
        parameters,
        variadic: None,
        calling_convention: calling_convention.map(str::to_string),
    }
}

fn target(architecture: &str, pointer_size: u64) -> Target {
    Target {
        architecture: architecture.to_string(),
        pointer_size,
        endian: Endian::Little,
    }
}

/// A document with one struct, one scalar and one function that has an address.
fn small_document(document_target: Target) -> IsfDocument {
    let mut document = IsfDocument::empty(document_target, None);
    document
        .base_types
        .insert("void".to_string(), base(BaseKind::Void, 0, false));
    document
        .base_types
        .insert("int32_t".to_string(), base(BaseKind::Int, 4, true));
    document.user_types.insert(
        "Thing".to_string(),
        user(
            CompositeKind::Struct,
            4,
            vec![("value", field(0, reference("int32_t")))],
        ),
    );
    document.functions.insert(
        "ping".to_string(),
        function(
            Some(0x1000),
            reference("int32_t"),
            vec![Parameter {
                name: Some("value".to_string()),
                ty: reference("int32_t"),
            }],
            None,
        ),
    );
    document
}

fn ffi_error(document: &IsfDocument, request: &FfiRequest<'_>) -> sym2isf::Error {
    generate_ffi(document, request).expect_err("the request must be refused")
}

fn assert_ffi_error(document: &IsfDocument, request: &FfiRequest<'_>, location: &str) {
    let error = ffi_error(document, request);
    assert_eq!(error.kind(), "FfiGeneration", "{error}");
    match error {
        sym2isf::Error::FfiGeneration {
            location: actual,
            detail,
        } => {
            assert_eq!(actual, location, "location of {detail}");
        }
        other => panic!("expected a generation failure, got {other}"),
    }
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

#[test]
fn an_empty_selection_is_refused() {
    let document = small_document(target("x86_64", 8));
    assert_ffi_error(&document, &FfiRequest::default(), "root types");
}

#[test]
fn unknown_and_ambiguous_roots_name_their_record() {
    let mut document = small_document(target("x86_64", 8));
    assert_ffi_error(
        &document,
        &FfiRequest {
            types: &["Nope"],
            ..FfiRequest::default()
        },
        "root type `Nope`",
    );

    // The same key in two tables cannot be resolved without guessing.
    document
        .base_types
        .insert("Thing".to_string(), base(BaseKind::Int, 4, true));
    assert_ffi_error(
        &document,
        &FfiRequest {
            types: &["Thing"],
            ..FfiRequest::default()
        },
        "root type `Thing`",
    );
}

#[test]
fn selecting_functions_needs_a_recorded_address() {
    let mut document = small_document(target("x86_64", 8));
    document.functions.insert(
        "silent".to_string(),
        function(None, reference("int32_t"), Vec::new(), None),
    );
    assert_ffi_error(
        &document,
        &FfiRequest {
            functions: &["silent"],
            ..FfiRequest::default()
        },
        "function `silent`",
    );
}

#[test]
fn an_offset_below_the_image_base_is_refused() {
    let mut document = small_document(target("x86_64", 8));
    document.metadata.sym2isf.image_base = Some(0x4000);
    assert_ffi_error(
        &document,
        &FfiRequest {
            functions: &["ping"],
            ..FfiRequest::default()
        },
        "function `ping`",
    );
}

#[test]
fn an_offset_that_does_not_fit_uintptr_is_refused() {
    let mut document = small_document(target("i386", 4));
    document.functions.insert(
        "far".to_string(),
        function(Some(0x1_0000_0000), reference("int32_t"), Vec::new(), None),
    );
    assert_ffi_error(
        &document,
        &FfiRequest {
            functions: &["far"],
            ..FfiRequest::default()
        },
        "function `far`",
    );

    // The same address is an ordinary 64-bit offset, so only the narrow target
    // is refused.
    let mut wide = small_document(target("x86_64", 8));
    wide.functions.insert(
        "far".to_string(),
        function(Some(0x1_0000_0000), reference("int32_t"), Vec::new(), None),
    );
    generate_ffi(
        &wide,
        &FfiRequest {
            functions: &["far"],
            ..FfiRequest::default()
        },
    )
    .expect("a 64-bit offset is representable");
}

// ---------------------------------------------------------------------------
// Declaration gates
// ---------------------------------------------------------------------------

#[test]
fn an_explicitly_aligned_scalar_is_refused() {
    let mut document = small_document(target("x86_64", 8));
    document
        .base_types
        .get_mut("int32_t")
        .expect("scalar")
        .alignment = Some(4);
    assert_ffi_error(
        &document,
        &FfiRequest {
            types: &["Thing"],
            ..FfiRequest::default()
        },
        "type `int32_t`",
    );
}

#[test]
fn a_32_bit_calling_convention_is_refused_where_it_is_recorded() {
    // At the top level.
    let mut document = small_document(target("i386", 4));
    document.functions.insert(
        "thiscall_entry".to_string(),
        function(
            Some(0x1000),
            reference("int32_t"),
            vec![Parameter {
                name: None,
                ty: TypeRef::Pointer {
                    subtype: Box::new(reference("int32_t")),
                    size: None,
                    qualifiers: Vec::new(),
                    reference_kind: None,
                },
            }],
            Some("thiscall"),
        ),
    );
    assert_ffi_error(
        &document,
        &FfiRequest {
            functions: &["thiscall_entry"],
            ..FfiRequest::default()
        },
        "function `thiscall_entry`",
    );

    // Inside a member's function type: dropping the convention would silently
    // make it the default one.
    let mut document = small_document(target("i386", 4));
    document.user_types.insert(
        "Holder".to_string(),
        user(
            CompositeKind::Struct,
            4,
            vec![(
                "callback",
                Field {
                    offset: 0,
                    ty: TypeRef::Pointer {
                        subtype: Box::new(TypeRef::Function {
                            return_type: Box::new(reference("int32_t")),
                            parameters: Vec::new(),
                            variadic: None,
                            calling_convention: Some("stdcall".to_string()),
                            qualifiers: Vec::new(),
                        }),
                        size: None,
                        qualifiers: Vec::new(),
                        reference_kind: None,
                    },
                    anonymous: None,
                },
            )],
        ),
    );
    assert_ffi_error(
        &document,
        &FfiRequest {
            types: &["Holder"],
            ..FfiRequest::default()
        },
        "type `Holder`, field `callback`",
    );
}

#[test]
fn a_by_value_aggregate_needs_the_explicit_switch() {
    let mut document = small_document(target("x86_64", 8));
    document.functions.insert(
        "takes_thing".to_string(),
        function(
            Some(0x1000),
            reference("int32_t"),
            vec![Parameter {
                name: None,
                ty: TypeRef::Struct {
                    name: "Thing".to_string(),
                    qualifiers: Vec::new(),
                },
            }],
            None,
        ),
    );
    assert_ffi_error(
        &document,
        &FfiRequest {
            functions: &["takes_thing"],
            ..FfiRequest::default()
        },
        "function `takes_thing`",
    );

    generate_ffi(
        &document,
        &FfiRequest {
            functions: &["takes_thing"],
            allow_by_value_aggregates: true,
            ..FfiRequest::default()
        },
    )
    .expect("the switch permits the signature");
}

#[test]
fn an_architecture_without_a_luajit_name_is_refused() {
    let document = small_document(target("riscv64", 8));
    assert_ffi_error(
        &document,
        &FfiRequest {
            types: &["Thing"],
            ..FfiRequest::default()
        },
        "root types",
    );
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn selection_order_and_repetition_do_not_change_the_module() {
    let mut document = small_document(target("x86_64", 8));
    document.enums.insert(
        "Code".to_string(),
        EnumType {
            size: 4,
            base: Some("int32_t".to_string()),
            constants: BTreeMap::from([
                ("low".to_string(), IntValue::Signed(-1)),
                ("high".to_string(), IntValue::Unsigned(7)),
            ]),
        },
    );
    document.functions.insert(
        "pong".to_string(),
        function(Some(0x2000), reference("int32_t"), Vec::new(), None),
    );

    let forwards = generate_ffi(
        &document,
        &FfiRequest {
            types: &["Thing", "Code"],
            functions: &["ping", "pong"],
            ..FfiRequest::default()
        },
    )
    .expect("selection");
    let backwards = generate_ffi(
        &document,
        &FfiRequest {
            types: &["Code", "Thing", "Code"],
            functions: &["pong", "ping", "pong", "ping"],
            ..FfiRequest::default()
        },
    )
    .expect("selection");
    assert_eq!(
        forwards, backwards,
        "the module must not depend on selection order or repetition"
    );

    // Every table key is the document's own string, never the cdef identifier.
    assert!(forwards.contains("M.types.enums[\"Code\"]"), "{forwards}");
    assert!(
        forwards.contains("M.functions[\"pong\"]"),
        "the function table is keyed by source name"
    );
}
