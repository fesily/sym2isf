//! Function declarations in the C layer: selection, prototype shape, naming and
//! the opt-in address table. No compiler is needed here; the TCC round trips live
//! in `tests/native_frontends.rs`.

use std::collections::BTreeMap;

use sym2isf::c::Request;
use sym2isf::isf::{Function, IsfDocument, Parameter};
use sym2isf::{
    BaseKind, BaseType, CompositeKind, Endian, Error, Field, Symbol, Target, TypeRef, UserType,
};

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
    variadic: bool,
    address: Option<u64>,
    calling_convention: Option<&str>,
) -> Function {
    Function {
        address,
        return_type,
        parameters,
        variadic: variadic.then_some(true),
        calling_convention: calling_convention.map(str::to_string),
    }
}

/// A document with one aggregate and a spread of function signatures.
fn document() -> IsfDocument {
    let mut document = IsfDocument::empty(target(), None);
    document
        .base_types
        .insert("void".to_string(), base(BaseKind::Void, 0, false));
    document
        .base_types
        .insert("int32_t".to_string(), base(BaseKind::Int, 4, true));
    document.user_types.insert(
        "Thing".to_string(),
        UserType {
            kind: CompositeKind::Struct,
            size: 4,
            fields: BTreeMap::from([(
                "value".to_string(),
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

    let mut insert = |name: &str, entry: Function| {
        document.functions.insert(name.to_string(), entry);
    };
    insert(
        "takes_void",
        function(
            reference("void"),
            Vec::new(),
            false,
            Some(0x1400_0100),
            None,
        ),
    );
    insert(
        "takes_variadic",
        function(
            reference("int32_t"),
            vec![parameter(Some("count"), reference("int32_t"))],
            true,
            None,
            None,
        ),
    );
    insert(
        "takes_thing",
        function(
            reference("void"),
            vec![parameter(
                Some("thing"),
                TypeRef::Struct {
                    name: "Thing".to_string(),
                    qualifiers: Vec::new(),
                },
            )],
            false,
            None,
            None,
        ),
    );
    insert(
        "takes_pointer",
        function(
            reference("void"),
            vec![parameter(Some("value"), pointer_to(reference("int32_t")))],
            false,
            None,
            None,
        ),
    );
    insert(
        "takes_callback",
        function(
            reference("void"),
            vec![parameter(
                Some("callback"),
                pointer_to(TypeRef::Function {
                    return_type: Box::new(reference("int32_t")),
                    parameters: vec![parameter(None, reference("int32_t"))],
                    variadic: None,
                    calling_convention: None,
                    qualifiers: Vec::new(),
                }),
            )],
            false,
            None,
            None,
        ),
    );
    // Hostile parameter names: a keyword, a leading digit, an empty slot and a
    // duplicate.
    insert(
        "names",
        function(
            reference("void"),
            vec![
                parameter(Some("value"), reference("int32_t")),
                parameter(Some("int"), reference("int32_t")),
                parameter(Some("9x"), reference("int32_t")),
                parameter(None, reference("int32_t")),
                parameter(Some("value"), reference("int32_t")),
            ],
            false,
            None,
            None,
        ),
    );
    insert(
        "??_7DNameNode@@6B@",
        function(reference("void"), Vec::new(), false, None, None),
    );
    insert(
        "convention",
        function(reference("void"), Vec::new(), false, None, Some("__cdecl")),
    );
    insert(
        "no_address",
        function(reference("void"), Vec::new(), false, None, None),
    );
    // A function returning a pointer to a function, and one returning a pointer
    // to an array: both put a `*` on the far side of a suffix.
    insert(
        "factory",
        function(
            pointer_to(TypeRef::Function {
                return_type: Box::new(reference("int32_t")),
                parameters: vec![parameter(None, reference("int32_t"))],
                variadic: None,
                calling_convention: None,
                qualifiers: Vec::new(),
            }),
            Vec::new(),
            false,
            None,
            None,
        ),
    );
    insert(
        "rows",
        function(
            pointer_to(TypeRef::Array {
                count: 3,
                subtype: Box::new(reference("int32_t")),
                qualifiers: Vec::new(),
            }),
            Vec::new(),
            false,
            None,
            None,
        ),
    );
    // A legal name that looks like the generator's own namespace stays verbatim.
    insert(
        "s2c_callback",
        function(reference("void"), Vec::new(), false, None, None),
    );
    // A recorded name on the sole `void` parameter must not reach the output.
    insert(
        "void_named",
        function(
            reference("void"),
            vec![parameter(Some("unused"), reference("void"))],
            false,
            None,
            None,
        ),
    );
    // The address table carries the document key as data.
    insert(
        "a*/b",
        function(
            reference("void"),
            Vec::new(),
            false,
            Some(0x1400_0300),
            None,
        ),
    );
    document
}

fn generation(document: &IsfDocument, request: &Request<'_>) -> String {
    sym2isf::c::generate(document, request).expect("generation succeeds")
}

fn c_error(document: &IsfDocument, request: &Request<'_>) -> String {
    let error = sym2isf::c::generate(document, request).expect_err("generation must fail");
    assert_eq!(error.kind(), "CGeneration", "{error:?}");
    error.to_string()
}

/// The identifier an `extern` prototype declares.
fn declared_name(line: &str) -> Option<&str> {
    let head = &line[..line.find('(')?];
    let trimmed = head.trim_end();
    let start = trimmed
        .rfind(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .map(|index| index + 1)
        .unwrap_or(0);
    Some(&trimmed[start..])
}

fn prototype_lines(source: &str) -> Vec<&str> {
    source
        .lines()
        .filter(|line| line.starts_with("extern "))
        .collect()
}

#[test]
fn prototypes_are_declarations_only() {
    let document = document();
    let source = generation(
        &document,
        &Request {
            functions: &[
                "takes_void",
                "takes_variadic",
                "takes_thing",
                "takes_pointer",
            ],
            ..Request::default()
        },
    );
    let lines = prototype_lines(&source);
    assert_eq!(lines.len(), 4, "{source}");
    let mut declared: Vec<&str> = Vec::new();
    for line in lines {
        assert!(
            line.ends_with(");"),
            "a prototype ends the declaration: {line}"
        );
        let name = declared_name(line).expect("a declared name");
        assert!(
            name.chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_'),
            "{name} is not a C identifier"
        );
        declared.push(name);
    }
    // A name C can spell is kept verbatim so a consumer can match it.
    assert!(declared.contains(&"takes_void"), "{declared:?}");
    assert!(declared.contains(&"takes_pointer"), "{declared:?}");
    // No binding, no ABI attribute, no address table unless asked for.
    assert!(!source.contains("s2c_addresses"), "{source}");
    assert!(!source.contains("__cdecl"), "{source}");
    assert!(!source.contains("address("), "{source}");
    // A by-value parameter needs its type declared, but not defined.
    assert!(
        source.contains("typedef struct s2c_s_Thing s2c_s_Thing;"),
        "{source}"
    );
    assert!(!source.contains("struct s2c_s_Thing {"), "{source}");
}

#[test]
fn parameter_lists_follow_c() {
    let document = document();
    let source = generation(
        &document,
        &Request {
            functions: &["takes_void", "takes_variadic", "names", "takes_callback"],
            ..Request::default()
        },
    );
    assert!(source.contains("(void);"), "{source}");
    assert!(source.contains(", ...);"), "variadic tail: {source}");
    // Only a name the document recorded and C can spell is kept; a keyword, a
    // leading digit, an unnamed slot and a repeat stay abstract instead of being
    // invented.
    let line = prototype_lines(&source)
        .into_iter()
        .find(|line| line.contains(" names("))
        .expect("the names prototype");
    assert!(line.contains("s2c_b_int32__t value,"), "{line}");
    assert_eq!(
        line.matches("value").count(),
        1,
        "a repeat is dropped: {line}"
    );
    assert!(!source.contains("s2c_p_"), "{source}");
    assert!(!line.contains("int,"), "a keyword stays abstract: {line}");
    // The callback parameter is a function pointer, not a function.
    assert!(source.contains("(*callback)"), "{source}");
}

#[test]
fn selection_is_order_independent() {
    let document = document();
    let names = ["takes_pointer", "takes_void", "??_7DNameNode@@6B@"];
    let forward = generation(
        &document,
        &Request {
            functions: &names,
            ..Request::default()
        },
    );
    let reversed = generation(
        &document,
        &Request {
            functions: &[
                "??_7DNameNode@@6B@",
                "takes_void",
                "takes_pointer",
                "takes_void",
            ],
            ..Request::default()
        },
    );
    assert_eq!(
        forward, reversed,
        "selector order and duplicates do not matter"
    );

    // Every function of the document, in table order, equals naming them all.
    let all: Vec<&str> = document.functions.keys().map(String::as_str).collect();
    let every = generation(
        &document,
        &Request {
            all_functions: true,
            ..Request::default()
        },
    );
    let named = generation(
        &document,
        &Request {
            functions: &all,
            ..Request::default()
        },
    );
    assert_eq!(every, named, "all_functions selects the same set");
}

#[test]
fn prototypes_keep_the_declarator_of_the_return_type() {
    let document = document();
    let source = generation(
        &document,
        &Request {
            functions: &["factory", "rows"],
            ..Request::default()
        },
    );
    // A function returning a pointer to a function, and one returning a pointer
    // to an array: the parameter list belongs to the outer function.
    assert!(
        source.contains("extern s2c_b_int32__t (*factory(void))(s2c_b_int32__t);"),
        "{source}"
    );
    assert!(
        source.contains("extern s2c_b_int32__t (*rows(void))[3];"),
        "{source}"
    );
}

#[test]
fn legal_function_names_are_kept_even_in_the_generator_namespace() {
    let document = document();
    let source = generation(
        &document,
        &Request {
            functions: &["s2c_callback"],
            ..Request::default()
        },
    );
    let line = prototype_lines(&source)[0];
    assert_eq!(
        declared_name(line),
        Some("s2c_callback"),
        "a spellable name is not rewritten: {line}"
    );
}

#[test]
fn a_named_void_parameter_is_still_an_empty_list() {
    let document = document();
    let source = generation(
        &document,
        &Request {
            functions: &["void_named"],
            ..Request::default()
        },
    );
    let line = prototype_lines(&source)[0];
    assert!(line.ends_with("(void);"), "{line}");
    assert!(!line.contains("unused"), "{line}");
}

#[test]
fn address_table_names_are_c_strings_of_the_document_key() {
    let document = document();
    let source = generation(
        &document,
        &Request {
            functions: &["a*/b"],
            with_addresses: true,
            ..Request::default()
        },
    );
    // The key reaches the table unchanged: `*/` is only defused in comments.
    assert!(
        source.contains("\"a*/b\", 0x0000000014000300ULL"),
        "{source}"
    );
    // The comment still defuses `*/`; only the table carries the raw key.
    assert_eq!(
        source.matches("\"a* /b\"").count(),
        1,
        "only the function comment is defused: {source}"
    );
}

#[test]
fn missing_functions_are_named() {
    let document = document();
    let message = c_error(
        &document,
        &Request {
            functions: &["nope"],
            ..Request::default()
        },
    );
    assert!(
        message.contains("cannot generate C for function `nope`"),
        "{message}"
    );
    assert!(message.contains("not found"), "{message}");
}

#[test]
fn documents_without_signatures_are_reported() {
    let mut document = document();
    document.functions.clear();
    let message = c_error(
        &document,
        &Request {
            functions: &["takes_void"],
            ..Request::default()
        },
    );
    assert!(
        message.contains("cannot generate C for functions"),
        "{message}"
    );
    assert!(message.contains("no function signatures"), "{message}");

    // The same document is fine when only types are requested.
    let source = generation(&document, &Request::types(&["Thing"]));
    assert!(source.contains("struct s2c_s_Thing {"), "{source}");
}

#[test]
fn address_table_is_opt_in() {
    let document = document();
    let plain = generation(
        &document,
        &Request {
            functions: &["takes_void", "no_address"],
            ..Request::default()
        },
    );
    assert!(!plain.contains("s2c_addresses"), "{plain}");

    let table = generation(
        &document,
        &Request {
            functions: &["takes_void", "no_address"],
            with_addresses: true,
            ..Request::default()
        },
    );
    assert!(
        table.contains("static const struct s2c_address s2c_addresses[]"),
        "{table}"
    );
    assert!(
        table.contains("\"takes_void\", 0x0000000014000100ULL"),
        "{table}"
    );
    assert!(
        table.contains("\"no_address\": no recorded address"),
        "an address is never invented: {table}"
    );

    // Asking for addresses when nothing has one is an error, not an empty table.
    let message = c_error(
        &document,
        &Request {
            functions: &["no_address"],
            with_addresses: true,
            ..Request::default()
        },
    );
    assert!(
        message.contains("cannot generate C for functions"),
        "{message}"
    );
    assert!(
        message.contains("no selected function has a recorded address"),
        "{message}"
    );
}

#[test]
fn addresses_need_a_function_selection() {
    let document = document();
    let message = c_error(
        &document,
        &Request {
            with_addresses: true,
            ..Request::default()
        },
    );
    assert!(
        message.contains("cannot generate C for functions"),
        "{message}"
    );
    assert!(
        message.contains("at least one selected function"),
        "{message}"
    );
}

#[test]
fn names_are_encoded_and_kept_verbatim_in_comments() {
    let document = document();
    let source = generation(
        &document,
        &Request {
            functions: &["??_7DNameNode@@6B@"],
            ..Request::default()
        },
    );
    // The original name only appears inside the escaped comment.
    assert!(
        source.contains("/* function \"??_7DNameNode@@6B@\" */"),
        "{source}"
    );
    let line = prototype_lines(&source)[0];
    let name = declared_name(line).expect("a declared name");
    assert!(name.starts_with("s2c_fn_"), "{line}");
    assert!(!name.contains('?') && !name.contains('@'), "{line}");
}

#[test]
fn symbol_entries_are_not_exported_as_code() {
    let mut document = document();
    document.symbols.insert(
        "packet_global".to_string(),
        Symbol {
            address: Some(0x1400_0200),
            ty: Some(reference("int32_t")),
        },
    );
    let source = generation(
        &document,
        &Request {
            functions: &["takes_void"],
            with_addresses: true,
            ..Request::default()
        },
    );
    // The table carries functions only, and a symbol name never becomes a C
    // declaration the layer would have to bind.
    assert!(!source.contains("packet_global"), "{source}");
    assert!(!source.contains("extern s2c_b_int32"), "{source}");
    let _ = Error::Message(String::new());
}
