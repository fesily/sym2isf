//! The SDK view: source names, a single `struct s2c_api` of function pointers
//! and the binder that resolves them from a module base. No compiler is needed
//! here; `tests/native_frontends.rs` calls a real shared object.

use std::collections::BTreeMap;

use sym2isf::c::{Request, View};
use sym2isf::isf::{EnumType, Function, IntValue, IsfDocument, Parameter};
use sym2isf::{BaseKind, BaseType, CompositeKind, Endian, Field, Target, TypeRef, UserType};

fn target(pointer_size: u64) -> Target {
    Target {
        architecture: if pointer_size == 8 { "x86_64" } else { "i386" }.to_string(),
        pointer_size,
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

fn reference(name: &str) -> TypeRef {
    TypeRef::Base {
        name: name.to_string(),
        qualifiers: Vec::new(),
    }
}

fn pointer_to(ty: TypeRef) -> TypeRef {
    TypeRef::Pointer {
        subtype: Box::new(ty),
        size: None,
        qualifiers: Vec::new(),
        reference_kind: None,
    }
}

fn parameter(name: Option<&str>, ty: TypeRef) -> Parameter {
    Parameter {
        name: name.map(str::to_string),
        ty,
    }
}

fn function(
    return_type: TypeRef,
    parameters: Vec<Parameter>,
    address: Option<u64>,
    convention: Option<&str>,
) -> Function {
    Function {
        address,
        return_type,
        parameters,
        variadic: None,
        calling_convention: convention.map(str::to_string),
    }
}

/// A document with an aggregate, an enum, an alias and a few functions.
fn document(pointer_size: u64, image_base: Option<u64>) -> IsfDocument {
    let mut document = IsfDocument::empty(target(pointer_size), image_base);
    document
        .base_types
        .insert("void".to_string(), base(BaseKind::Void, 0, false));
    document
        .base_types
        .insert("int32_t".to_string(), base(BaseKind::Int, 4, true));
    document.user_types.insert(
        "Packet".to_string(),
        UserType {
            kind: CompositeKind::Struct,
            size: 8,
            fields: BTreeMap::from([
                (
                    "value".to_string(),
                    Field {
                        offset: 0,
                        ty: reference("int32_t"),
                        anonymous: None,
                    },
                ),
                (
                    "counter".to_string(),
                    Field {
                        offset: 4,
                        ty: TypeRef::Typedef {
                            name: "word_t".to_string(),
                            qualifiers: Vec::new(),
                        },
                        anonymous: None,
                    },
                ),
            ]),
            alignment: None,
            incomplete: None,
            unsupported_reason: None,
        },
    );
    document
        .typedefs
        .insert("word_t".to_string(), reference("int32_t"));
    document.enums.insert(
        "SignedCode".to_string(),
        EnumType {
            size: 4,
            base: Some("int32_t".to_string()),
            constants: BTreeMap::from([("CODE_NEG".to_string(), IntValue::Signed(-3))]),
        },
    );
    document.functions.insert(
        "packet_callback".to_string(),
        function(
            reference("int32_t"),
            vec![
                parameter(
                    Some("packet"),
                    pointer_to(TypeRef::Struct {
                        name: "Packet".to_string(),
                        qualifiers: Vec::new(),
                    }),
                ),
                parameter(Some("delta"), reference("int32_t")),
            ],
            Some(image_base.map_or(0x11_96, |base| base + 0x11_96)),
            Some("near_cdecl"),
        ),
    );
    document.functions.insert(
        "endian_name".to_string(),
        function(
            pointer_to(reference("int32_t")),
            Vec::new(),
            Some(image_base.map_or(0x11_a1, |base| base + 0x11_a1)),
            None,
        ),
    );
    document
}

fn sdk(document: &IsfDocument, request: &Request<'_>) -> String {
    sym2isf::c::generate(document, request).expect("generation succeeds")
}

fn c_error(document: &IsfDocument, request: &Request<'_>) -> String {
    let error = sym2isf::c::generate(document, request).expect_err("generation must fail");
    assert_eq!(error.kind(), "CGeneration", "{error:?}");
    error.to_string()
}

fn base_request<'a>(types: &'a [&'a str], functions: &'a [&'a str]) -> Request<'a> {
    Request {
        types,
        functions,
        view: View::Sdk,
        ..Request::default()
    }
}

#[test]
fn sdk_uses_source_names_and_standard_scalars() {
    let document = document(8, None);
    let source = sdk(
        &document,
        &base_request(&["Packet"], &["packet_callback", "endian_name"]),
    );
    // Source names, no prefixed aliases for things C can spell.
    assert!(source.contains("struct Packet {"), "{source}");
    assert!(source.contains("typedef struct Packet Packet;"), "{source}");
    assert!(source.contains("int32_t value;"), "{source}");
    assert!(!source.contains("s2c_s_Packet"), "{source}");
    assert!(!source.contains("s2c_b_int32"), "{source}");
    // The alias survives, its own name kept.
    assert!(source.contains("typedef int32_t word_t;"), "{source}");
    // Scalars are the standard fixed-width types, and the API is one struct.
    assert!(source.contains("struct s2c_api {"), "{source}");
    assert!(
        source.contains("int32_t (*packet_callback)(Packet *packet, int32_t delta);"),
        "{source}"
    );
    assert!(
        source.contains("typedef struct s2c_api s2c_api;"),
        "{source}"
    );
    // Resolution is injected by the caller: the header only states the name and
    // the recorded offset, and never computes a module address.
    assert!(
        source.contains("typedef void (*s2c_entry)(void);"),
        "{source}"
    );
    assert!(
        source.contains("typedef s2c_entry (*s2c_resolver)(const char *name, uintptr_t offset);"),
        "{source}"
    );
    assert!(
        source.contains("static inline void s2c_bind(struct s2c_api *api, s2c_resolver resolve)"),
        "{source}"
    );
    assert!(!source.contains("uintptr_t base"), "{source}");
    assert!(!source.contains("base + "), "{source}");
    // Nothing is declared for a linker to resolve.
    assert!(!source.contains("extern "), "{source}");
    assert!(!source.contains("s2c_addresses"), "{source}");
    assert!(source.starts_with("#ifndef S2C_SDK_H"), "{source}");
    assert!(
        source.trim_end().ends_with("#endif /* S2C_SDK_H */"),
        "{source}"
    );
}

#[test]
fn offsets_are_relative_to_the_image_base() {
    // With an image base the resolver receives address - image_base.
    let with_base = document(8, Some(0x1_4000_0000));
    let source = sdk(&with_base, &base_request(&["Packet"], &["packet_callback"]));
    assert!(
        source.contains("resolve(\"packet_callback\", (uintptr_t)0x0000000000001196ULL)"),
        "{source}"
    );

    // Without one the recorded address is already the offset (a shared object).
    let without_base = document(8, None);
    let source = sdk(&without_base, &base_request(&["Packet"], &["endian_name"]));
    assert!(
        source.contains("resolve(\"endian_name\", (uintptr_t)0x00000000000011a1ULL)"),
        "{source}"
    );

    // An address below the recorded base is a document error, not a wrap.
    let mut broken = document(8, Some(0x1_4000_0000));
    broken.functions.get_mut("packet_callback").unwrap().address = Some(0x10);
    let message = c_error(&broken, &base_request(&["Packet"], &["packet_callback"]));
    assert!(message.contains("function `packet_callback`"), "{message}");
    assert!(message.contains("below image base"), "{message}");
}

#[test]
fn by_value_aggregates_are_refused_unless_allowed() {
    let mut document = document(8, None);
    document.functions.insert(
        "takes_packet".to_string(),
        function(
            reference("void"),
            vec![parameter(
                Some("packet"),
                TypeRef::Struct {
                    name: "Packet".to_string(),
                    qualifiers: Vec::new(),
                },
            )],
            Some(0x2000),
            None,
        ),
    );
    let request = base_request(&["Packet"], &["takes_packet"]);
    let message = c_error(&document, &request);
    assert!(message.contains("function `takes_packet`"), "{message}");
    assert!(
        message.contains("takes aggregate `Packet` by value"),
        "{message}"
    );

    let allowed = Request {
        allow_by_value_aggregates: true,
        ..request
    };
    let source = sdk(&document, &allowed);
    assert!(
        source.contains("void (*takes_packet)(Packet packet);"),
        "{source}"
    );
}

#[test]
fn the_resolver_receives_the_source_name() {
    let mut document = document(8, None);
    document.functions.insert(
        "??_7DNameNode@@6B@".to_string(),
        function(reference("void"), Vec::new(), Some(0x2000), None),
    );
    let source = sdk(&document, &base_request(&[], &["??_7DNameNode@@6B@"]));
    // The member is a legal identifier, but resolution is keyed by the source
    // name, so the caller can look it up in its own tables.
    assert!(
        source.contains("resolve(\"??_7DNameNode@@6B@\""),
        "{source}"
    );
    assert!(
        source.contains("(*s2c_fn_"),
        "a mangled member is encoded: {source}"
    );
}

#[test]
fn sign_conventions_matter_on_a_32_bit_target() {
    let mut document = document(4, None);
    document
        .functions
        .get_mut("packet_callback")
        .unwrap()
        .calling_convention = Some("near_stdcall".to_string());
    let message = c_error(&document, &base_request(&["Packet"], &["packet_callback"]));
    assert!(message.contains("function `packet_callback`"), "{message}");
    assert!(
        message.contains("`near_stdcall` is not supported yet"),
        "{message}"
    );

    // x86-64 has a single convention, so the recorded name is not emitted.
    let mut wide = crate::document(8, None);
    wide.functions
        .get_mut("packet_callback")
        .unwrap()
        .calling_convention = Some("near_stdcall".to_string());
    let source = sdk(&wide, &base_request(&["Packet"], &["packet_callback"]));
    assert!(!source.contains("stdcall"), "{source}");
}

#[test]
fn an_sdk_needs_a_function_and_never_links() {
    let document = document(8, None);
    let message = c_error(
        &document,
        &Request {
            types: &["Packet"],
            view: View::Sdk,
            ..Request::default()
        },
    );
    assert!(
        message.contains("cannot generate C for functions"),
        "{message}"
    );
    assert!(
        message.contains("the SDK view needs at least one selected function"),
        "{message}"
    );

    let source = sdk(&document, &base_request(&[], &["endian_name"]));
    assert!(!source.contains("extern "), "{source}");
    assert!(source.contains("struct s2c_api {"), "{source}");
}

#[test]
fn selection_is_order_independent_in_the_sdk_view() {
    let document = document(8, None);
    let forward = sdk(
        &document,
        &base_request(&["Packet"], &["endian_name", "packet_callback"]),
    );
    let reversed = sdk(
        &document,
        &base_request(
            &["Packet"],
            &["packet_callback", "endian_name", "packet_callback"],
        ),
    );
    assert_eq!(
        forward, reversed,
        "selector order and duplicates do not matter"
    );
    // Members and bindings are sorted by source name.
    let members: Vec<usize> = ["endian_name", "packet_callback"]
        .iter()
        .map(|name| forward.find(&format!("(*{name})(")).expect("member"))
        .collect();
    assert!(members[0] < members[1], "declaration order");
    let bindings: Vec<usize> = ["api->endian_name", "api->packet_callback"]
        .iter()
        .map(|name| forward.find(name).expect("binding"))
        .collect();
    assert!(bindings[0] < bindings[1], "binding order");
}

#[test]
fn tautological_typedefs_are_skipped() {
    // A document alias that spells exactly like its expansion declares nothing;
    // the header must not repeat `typedef int32_t int32_t;`.
    let mut document = document(8, None);
    document
        .typedefs
        .insert("int32_t".to_string(), reference("int32_t"));
    document
        .user_types
        .get_mut("Packet")
        .unwrap()
        .fields
        .insert(
            "counter".to_string(),
            Field {
                offset: 4,
                ty: TypeRef::Typedef {
                    name: "int32_t".to_string(),
                    qualifiers: Vec::new(),
                },
                anonymous: None,
            },
        );
    let source = sdk(&document, &base_request(&["Packet"], &["endian_name"]));
    assert!(!source.contains("typedef int32_t int32_t;"), "{source}");
}

fn opaque_base(size: u64) -> BaseType {
    BaseType {
        kind: BaseKind::Opaque,
        size,
        signed: false,
        endian: Endian::Little,
        alignment: None,
        unsupported_reason: Some("record members are not representable".to_string()),
    }
}

#[test]
fn opaque_units_are_aggregates_for_the_abi() {
    let mut document = document(8, None);
    document
        .base_types
        .insert("Blob".to_string(), opaque_base(8));
    document
        .typedefs
        .insert("blob_t".to_string(), reference("Blob"));
    document.functions.insert(
        "takes_blob".to_string(),
        function(
            reference("void"),
            vec![parameter(Some("blob"), reference("Blob"))],
            Some(0x3000),
            None,
        ),
    );

    // An opaque unit is published as a struct, so passing it by value is the
    // same unproven ABI assumption as a struct.
    let message = c_error(&document, &base_request(&[], &["takes_blob"]));
    assert!(
        message.contains("takes aggregate `Blob` by value"),
        "{message}"
    );

    // A typedef does not hide it.
    document.functions.insert(
        "takes_alias".to_string(),
        function(
            reference("void"),
            vec![parameter(
                Some("blob"),
                TypeRef::Typedef {
                    name: "blob_t".to_string(),
                    qualifiers: Vec::new(),
                },
            )],
            Some(0x3010),
            None,
        ),
    );
    let message = c_error(&document, &base_request(&[], &["takes_alias"]));
    assert!(
        message.contains("takes aggregate `Blob` by value"),
        "{message}"
    );

    // A pointer to it stays legal.
    document.functions.insert(
        "takes_blob_pointer".to_string(),
        function(
            reference("void"),
            vec![parameter(Some("blob"), pointer_to(reference("Blob")))],
            Some(0x3020),
            None,
        ),
    );
    let source = sdk(&document, &base_request(&[], &["takes_blob_pointer"]));
    assert!(
        source.contains("void (*takes_blob_pointer)(Blob *blob);"),
        "{source}"
    );
}

#[test]
fn opaque_units_keep_the_layout_spelling() {
    let mut document = document(8, None);
    document
        .base_types
        .insert("Blob".to_string(), opaque_base(8));

    // The shipped layout view keeps its anonymous struct: byte compatibility.
    let layout = sdk(
        &document,
        &Request {
            types: &["Blob"],
            view: View::Layout,
            ..Request::default()
        },
    );
    assert!(
        layout.contains("typedef struct { unsigned char s2c_storage[8]; } s2c_b_Blob;"),
        "{layout}"
    );

    // The SDK header names the tag so `struct Blob` works as well as `Blob`.
    document.functions.insert(
        "endian_name".to_string(),
        function(reference("void"), Vec::new(), Some(0x11a1), None),
    );
    let source = sdk(
        &document,
        &Request {
            types: &["Blob"],
            functions: &["endian_name"],
            view: View::Sdk,
            ..Request::default()
        },
    );
    assert!(
        source.contains("typedef struct Blob { unsigned char bytes[8]; } Blob;"),
        "{source}"
    );
}

#[test]
fn reserved_header_names_fall_back_to_the_encoded_form() {
    // `int32_t` is a legal document key, but declaring a struct with that name
    // would collide with <stdint.h>.
    let mut document = document(8, None);
    document.user_types.insert(
        "int32_t".to_string(),
        UserType {
            kind: CompositeKind::Struct,
            size: 4,
            fields: BTreeMap::from([(
                "b".to_string(),
                Field {
                    offset: 0,
                    ty: reference("int32_t"),
                    anonymous: None,
                },
            )]),
            alignment: None,
            incomplete: None,
            unsupported_reason: None,
        },
    );
    document.functions.insert(
        "takes_reserved".to_string(),
        function(
            reference("void"),
            vec![parameter(
                Some("value"),
                pointer_to(TypeRef::Struct {
                    name: "int32_t".to_string(),
                    qualifiers: Vec::new(),
                }),
            )],
            Some(0x4000),
            None,
        ),
    );
    let source = sdk(&document, &base_request(&[], &["takes_reserved"]));
    assert!(!source.contains("typedef struct int32_t"), "{source}");
    assert!(source.contains("struct s2c_s_int32__t"), "{source}");
}

#[test]
fn the_binder_parameters_never_shadow_a_type() {
    // A document type called `api` must not be hidden by the binder parameter.
    let mut document = document(8, None);
    document.user_types.insert(
        "api".to_string(),
        UserType {
            kind: CompositeKind::Struct,
            size: 4,
            fields: BTreeMap::from([(
                "b".to_string(),
                Field {
                    offset: 0,
                    ty: reference("int32_t"),
                    anonymous: None,
                },
            )]),
            alignment: None,
            incomplete: None,
            unsupported_reason: None,
        },
    );
    document.functions.insert(
        "takes_api".to_string(),
        function(
            reference("void"),
            vec![parameter(
                Some("value"),
                pointer_to(TypeRef::Struct {
                    name: "api".to_string(),
                    qualifiers: Vec::new(),
                }),
            )],
            Some(0x5000),
            None,
        ),
    );
    let source = sdk(&document, &base_request(&["api"], &["takes_api"]));
    assert!(
        source.contains("static inline void s2c_bind(struct s2c_api *api_2, s2c_resolver resolve)"),
        "{source}"
    );
    assert!(source.contains("api_2->takes_api"), "{source}");
    // The cast still names the typedef, which the parameter no longer hides.
    assert!(source.contains("(void (*)(api *))"), "{source}");
}

#[test]
fn parameter_names_do_not_hide_a_type_used_later() {
    // In C the first parameter's name is in scope for the rest of the list, so
    // naming it `Packet` would make the second `Packet *` unparsable.
    let mut document = document(8, None);
    let packet_pointer = || {
        pointer_to(TypeRef::Struct {
            name: "Packet".to_string(),
            qualifiers: Vec::new(),
        })
    };
    document.functions.insert(
        "twin".to_string(),
        function(
            reference("void"),
            vec![
                parameter(Some("Packet"), packet_pointer()),
                parameter(Some("other"), packet_pointer()),
            ],
            Some(0x6000),
            None,
        ),
    );
    let source = sdk(&document, &base_request(&["Packet"], &["twin"]));
    assert!(!source.contains("Packet *Packet"), "{source}");
    assert!(source.contains("Packet *"), "{source}");
    assert!(source.contains("*other"), "{source}");
}

#[test]
fn sdk_member_names_keep_a_leading_underscore() {
    let mut document = document(8, None);
    document.functions.insert(
        "_helper".to_string(),
        function(reference("void"), Vec::new(), Some(0x7000), None),
    );
    let source = sdk(&document, &base_request(&[], &["_helper"]));
    assert!(source.contains("(*_helper)(void)"), "{source}");
    assert!(source.contains("resolve(\"_helper\""), "{source}");
    assert!(!source.contains("s2c_fn___helper"), "{source}");
}

#[test]
fn pointer_units_must_match_the_target_width() {
    let mut document = document(8, None);
    document.base_types.insert(
        "short_pointer".to_string(),
        base(BaseKind::Pointer, 4, false),
    );
    document.functions.insert(
        "takes_short_pointer".to_string(),
        function(
            reference("void"),
            vec![parameter(Some("value"), reference("short_pointer"))],
            Some(0x8000),
            None,
        ),
    );
    let message = c_error(&document, &base_request(&[], &["takes_short_pointer"]));
    assert!(message.contains("type `short_pointer`"), "{message}");
    assert!(message.contains("pointer unit is 4 bytes"), "{message}");
}

#[test]
fn character_units_keep_a_character_spelling() {
    let mut document = document(8, None);
    document
        .base_types
        .insert("char".to_string(), base(BaseKind::Char, 1, true));
    document
        .base_types
        .insert("u8c".to_string(), base(BaseKind::Char, 1, false));
    document.functions.insert(
        "takes_chars".to_string(),
        function(
            reference("void"),
            vec![
                parameter(Some("text"), pointer_to(reference("char"))),
                parameter(Some("raw"), pointer_to(reference("u8c"))),
            ],
            Some(0x9500),
            None,
        ),
    );
    let source = sdk(&document, &base_request(&[], &["takes_chars"]));
    assert!(source.contains("char *text"), "{source}");
    assert!(source.contains("unsigned char *raw"), "{source}");
}

#[test]
fn an_explicitly_aligned_scalar_is_refused() {
    let mut document = document(8, None);
    let mut aligned = base(BaseKind::Int, 8, false);
    aligned.alignment = Some(8);
    document
        .base_types
        .insert("aligned_word".to_string(), aligned);
    document.functions.insert(
        "takes_aligned".to_string(),
        function(
            reference("void"),
            vec![parameter(Some("value"), reference("aligned_word"))],
            Some(0x9000),
            None,
        ),
    );
    let message = c_error(&document, &base_request(&[], &["takes_aligned"]));
    assert!(message.contains("type `aligned_word`"), "{message}");
    assert!(
        message.contains("explicitly aligned scalar cannot be spelled"),
        "{message}"
    );
}

#[test]
fn a_selected_scalar_is_validated_even_without_a_typedef() {
    let mut document = document(8, None);
    document
        .base_types
        .insert("wide_float".to_string(), base(BaseKind::Float, 16, true));
    // The root is selected but never referenced: the SDK still has to validate it.
    let message = c_error(
        &document,
        &Request {
            types: &["wide_float"],
            functions: &["endian_name"],
            view: View::Sdk,
            ..Request::default()
        },
    );
    assert!(message.contains("type `wide_float`"), "{message}");
    assert!(message.contains("floating point width 16"), "{message}");
}
