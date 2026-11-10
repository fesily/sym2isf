//! Layout-preserving C declarations from a normalized ISF document.
//!
//! The generator never parses a debug container: it consumes the already
//! normalized tables of an [`IsfDocument`] and renders the records it can
//! describe statically. Sizes, offsets and bit-field slices come from the
//! document itself, so the emitted translation unit is a *memory layout view*:
//! it does not bind symbols, call target functions or promise the target ABI.
//!
//! Plain members keep their direct field access. Bit-fields are stored as the
//! exact byte slices the document recorded and are read and written by
//! generated accessors, so the output never depends on a compiler's bit-field
//! allocation rules. Aggregates are packed and padded explicitly, so no target
//! alignment is inferred from offsets the document does not record.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

use crate::error::{Error, Result};
use crate::isf::type_size;
use crate::isf::{
    BaseKind, BaseType, CompositeKind, Function as IsfFunction, IntValue, IsfDocument, Parameter,
    Qualifier, TypeRef, UserType,
};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Which product a translation unit is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum View {
    /// A byte-exact memory layout view: prefixed names, packed aggregates and
    /// `extern` prototypes, with no address unless one is asked for.
    #[default]
    Layout,
    /// An SDK view: source names, ABI-spelled scalars, one `struct s2c_api` of
    /// function pointers and a binder that asks the caller's resolver for each
    /// address.
    Sdk,
}

/// Which declarations a translation unit should carry.
///
/// Selection is by exact table key, never by prefix or fuzzy match, and the
/// order in which names are given never changes the output.
#[derive(Clone, Copy, Debug, Default)]
pub struct Request<'a> {
    /// Root type names: keys of `base_types`, `user_types`, `enums` or `typedefs`.
    pub types: &'a [&'a str],
    /// Function names: keys of `functions`.
    pub functions: &'a [&'a str],
    /// Select every entry of `functions` instead of naming them.
    pub all_functions: bool,
    /// Emit the recorded addresses as a static data table (layout view only).
    pub with_addresses: bool,
    /// Which product to render.
    pub view: View,
    /// Allow an aggregate passed or returned by value in the SDK view.
    pub allow_by_value_aggregates: bool,
}

impl<'a> Request<'a> {
    /// A request for the given types and nothing else.
    pub fn types(types: &'a [&'a str]) -> Self {
        Request {
            types,
            ..Request::default()
        }
    }
}

/// Render a self-contained C translation unit for one [`Request`].
///
/// Every selected type must name exactly one entry of `base_types`,
/// `user_types`, `enums` or `typedefs`, and every selected function one entry of
/// `functions`. The result is a pure function of the document and the request:
/// the order in which names are given does not change the output.
pub fn generate(document: &IsfDocument, request: &Request<'_>) -> Result<String> {
    document.validate()?;
    let target = &document.metadata.sym2isf.target;
    if target.endian.is_big() {
        return Err(cg(
            &Loc::Roots,
            "only little-endian targets can be described as C",
        ));
    }
    if !matches!(target.pointer_size, 4 | 8) {
        return Err(cg(
            &Loc::Roots,
            format!(
                "target pointer size {} is not 4 or 8 bytes",
                target.pointer_size
            ),
        ));
    }
    if request.with_addresses && request.functions.is_empty() && !request.all_functions {
        return Err(cg(
            &Loc::Functions,
            "an address table needs at least one selected function",
        ));
    }
    if request.types.is_empty() && request.functions.is_empty() && !request.all_functions {
        return Err(cg(
            &Loc::Roots,
            "at least one root type or function is required",
        ));
    }

    let mut walker = Walker::new(document);
    let mut selected: BTreeSet<&str> = BTreeSet::new();
    selected.extend(request.types.iter().copied());
    for name in selected {
        let mut tables = 0usize;
        if document.base_types.contains_key(name) {
            tables += 1;
        }
        if document.user_types.contains_key(name) {
            tables += 1;
        }
        if document.enums.contains_key(name) {
            tables += 1;
        }
        if document.typedefs.contains_key(name) {
            tables += 1;
        }
        let loc = Loc::Root(name);
        match tables {
            0 => return Err(cg(&loc, "type not found")),
            1 => {}
            _ => return Err(cg(&loc, "name matches more than one type table")),
        }
        if document.base_types.contains_key(name) {
            walker.used.scalars.insert(name.to_string());
        } else if document.user_types.contains_key(name) {
            walker.visit_aggregate(name, Mode::Complete, &loc)?;
        } else if document.enums.contains_key(name) {
            walker.used.enums.insert(name.to_string());
        } else {
            let reference = TypeRef::Typedef {
                name: name.to_string(),
                qualifiers: Vec::new(),
            };
            walker.visit(&reference, Mode::Complete, &loc)?;
        }
    }
    walker.drain()?;

    let mut functions: Vec<String> = Vec::new();
    if request.all_functions {
        functions.extend(document.functions.keys().cloned());
    }
    functions.extend(request.functions.iter().map(|name| (*name).to_string()));
    functions.sort();
    functions.dedup();
    let wanted_functions = request.all_functions || !request.functions.is_empty();
    if wanted_functions && document.functions.is_empty() {
        return Err(cg(
            &Loc::Functions,
            "the document carries no function signatures; convert without types-only",
        ));
    }
    for name in &functions {
        let function = document
            .functions
            .get(name)
            .ok_or_else(|| cg(&Loc::Function(name), "not found"))?;
        let loc = Loc::Function(name);
        walker.visit_signature(
            &function.return_type,
            &function.parameters,
            function.variadic,
            &loc,
        )?;
    }
    walker.drain()?;

    Generator::new(
        document,
        walker.used,
        functions,
        request.with_addresses,
        request.view,
        request.allow_by_value_aggregates,
    )?
    .emit()
}

fn cg(loc: &Loc<'_>, detail: impl Into<String>) -> Error {
    Error::CGeneration {
        location: loc.to_string(),
        detail: detail.into(),
    }
}

/// Where a generated declaration lives, used verbatim in error messages.
enum Loc<'a> {
    Roots,
    Root(&'a str),
    Type(&'a str),
    Field(&'a str, &'a str),
    Functions,
    Function(&'a str),
}

impl fmt::Display for Loc<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Loc::Roots => f.write_str("root types"),
            Loc::Root(name) => write!(f, "root type `{name}`"),
            Loc::Type(name) => write!(f, "type `{name}`"),
            Loc::Field(ty, field) => write!(f, "type `{ty}`, field `{field}`"),
            Loc::Functions => f.write_str("functions"),
            Loc::Function(name) => write!(f, "function `{name}`"),
        }
    }
}

// ---------------------------------------------------------------------------
// Closure: which declarations the roots need
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Mode {
    /// A `struct`/`union` tag is enough; the definition is not needed.
    Declare,
    /// The complete definition is needed.
    Complete,
}

#[derive(Default)]
struct Used {
    scalars: BTreeSet<String>,
    enums: BTreeSet<String>,
    aliases: BTreeSet<String>,
    alias_modes: BTreeMap<String, Mode>,
    declared: BTreeSet<String>,
    complete: BTreeSet<String>,
    pending: BTreeSet<String>,
}

struct Walker<'a> {
    doc: &'a IsfDocument,
    pointer_size: u64,
    used: Used,
}

impl<'a> Walker<'a> {
    fn new(doc: &'a IsfDocument) -> Self {
        Walker {
            doc,
            pointer_size: doc.metadata.sym2isf.target.pointer_size,
            used: Used::default(),
        }
    }

    /// Visit every definition this reference needs.
    fn visit(&mut self, ty: &TypeRef, mode: Mode, loc: &Loc<'_>) -> Result<()> {
        match ty {
            TypeRef::Base { name, .. } => {
                if !self.doc.base_types.contains_key(name) {
                    return Err(cg(loc, format!("missing base type `{name}`")));
                }
                self.used.scalars.insert(name.clone());
                Ok(())
            }
            TypeRef::Struct { name, .. } | TypeRef::Union { name, .. } => {
                self.visit_aggregate(name, mode, loc)
            }
            TypeRef::Enum { name, .. } => {
                if !self.doc.enums.contains_key(name) {
                    return Err(cg(loc, format!("missing enum `{name}`")));
                }
                self.used.enums.insert(name.clone());
                Ok(())
            }
            TypeRef::Typedef { name, .. } => {
                if self
                    .used
                    .alias_modes
                    .get(name)
                    .is_some_and(|seen| *seen >= mode)
                {
                    return Ok(());
                }
                self.used.alias_modes.insert(name.clone(), mode);
                self.used.aliases.insert(name.clone());
                let target = self
                    .doc
                    .typedefs
                    .get(name)
                    .ok_or_else(|| cg(loc, format!("missing typedef `{name}`")))?;
                self.visit(target, mode, loc)
            }
            TypeRef::Pointer { subtype, size, .. } => {
                let effective = size.unwrap_or(self.pointer_size);
                if effective != self.pointer_size {
                    return Err(cg(
                        loc,
                        format!(
                            "pointer of {effective} bytes does not match the target pointer size {}",
                            self.pointer_size
                        ),
                    ));
                }
                self.visit(subtype, Mode::Declare, loc)
            }
            TypeRef::Array { subtype, .. } => self.visit(subtype, Mode::Complete, loc),
            TypeRef::Bitfield {
                bit_length,
                bit_position,
                ty,
                ..
            } => {
                if !(1..=64).contains(bit_length) {
                    return Err(cg(
                        loc,
                        format!("bit-field width {bit_length} is outside 1..=64"),
                    ));
                }
                let storage_name = match &**ty {
                    TypeRef::Base { name, .. } => name,
                    _ => return Err(cg(loc, "bit-field storage is not a base type")),
                };
                let storage = self.doc.base_types.get(storage_name).ok_or_else(|| {
                    cg(loc, format!("missing bit-field storage `{storage_name}`"))
                })?;
                if storage.endian.is_big() {
                    return Err(cg(
                        loc,
                        format!("bit-field storage `{storage_name}` is big-endian"),
                    ));
                }
                let width = storage
                    .size
                    .checked_mul(8)
                    .ok_or_else(|| cg(loc, "bit-field storage width overflows"))?;
                let end = bit_position
                    .checked_add(*bit_length)
                    .ok_or_else(|| cg(loc, "bit-field range overflows"))?;
                if end > width {
                    return Err(cg(
                        loc,
                        format!(
                            "bit-field bits {bit_position}..{end} exceed storage `{storage_name}` width {width}"
                        ),
                    ));
                }
                Ok(())
            }
            TypeRef::Function {
                return_type,
                parameters,
                variadic,
                ..
            } => self.visit_signature(return_type, parameters, *variadic, loc),
        }
    }

    /// Visit the declarations a function signature needs.
    fn visit_signature(
        &mut self,
        return_type: &TypeRef,
        parameters: &[Parameter],
        variadic: Option<bool>,
        loc: &Loc<'_>,
    ) -> Result<()> {
        if parameters.is_empty() && variadic == Some(true) {
            return Err(cg(
                loc,
                "a variadic function needs at least one fixed parameter",
            ));
        }
        self.visit(return_type, Mode::Declare, loc)?;
        for parameter in parameters {
            self.visit(&parameter.ty, Mode::Declare, loc)?;
        }
        Ok(())
    }

    fn visit_aggregate(&mut self, name: &str, mode: Mode, loc: &Loc<'_>) -> Result<()> {
        let user = self
            .doc
            .user_types
            .get(name)
            .ok_or_else(|| cg(loc, format!("missing user type `{name}`")))?;
        if user.incomplete == Some(true) {
            self.used.declared.insert(name.to_string());
            return Ok(());
        }
        match mode {
            Mode::Complete => {
                if user.size == 0 {
                    return Err(cg(loc, format!("complete aggregate `{name}` has size 0")));
                }
                if self.used.complete.insert(name.to_string()) {
                    self.used.pending.insert(name.to_string());
                }
            }
            Mode::Declare => {
                if !self.used.complete.contains(name) {
                    self.used.declared.insert(name.to_string());
                }
            }
        }
        Ok(())
    }

    /// Expand every aggregate that needs a definition, in name order.
    fn drain(&mut self) -> Result<()> {
        while let Some(name) = self.used.pending.pop_first() {
            let fields: Vec<(String, TypeRef)> = self.doc.user_types[&name]
                .fields
                .iter()
                .map(|(key, field)| (key.clone(), field.ty.clone()))
                .collect();
            for (field, ty) in fields {
                let loc = Loc::Field(&name, &field);
                self.visit(&ty, Mode::Complete, &loc)?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// C type and declarator rendering
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum CType {
    Base(String),
    Qualified(Vec<Qualifier>, Box<CType>),
    Pointer(Box<CType>, Vec<Qualifier>),
    Array(Box<CType>, u64),
    Function(Box<CType>, Vec<CType>, bool),
}

fn qualifier_prefix(qualifiers: &[Qualifier]) -> String {
    let mut out = String::new();
    for qualifier in qualifiers {
        out.push_str(match qualifier {
            Qualifier::Const => "const ",
            Qualifier::Volatile => "volatile ",
            Qualifier::Restrict => "restrict ",
        });
    }
    out
}

fn merge_qualifiers(first: &[Qualifier], second: &[Qualifier]) -> Vec<Qualifier> {
    let mut merged: Vec<Qualifier> = first.iter().chain(second.iter()).copied().collect();
    merged.sort();
    merged.dedup();
    merged
}

/// Render one declaration of `name` with the given type.
///
/// The declarator is built by walking the type outside in and inserting each
/// operator at the identifier, which keeps `T (*p)[N]`, `T *p[N]`, function
/// pointers and arrays of function pointers correct without string patching.
fn declare(ty: &CType, name: &str) -> String {
    declare_with_names(ty, name, None)
}

/// Render one declaration, naming the parameters of the outermost function.
fn declare_with_names(ty: &CType, name: &str, names: Option<&[Option<String>]>) -> String {
    let mut text = String::from("?");
    let mut simple = true;
    let mut names = names;
    walk_type(ty, &mut text, &mut simple, &mut names);
    let declarator = text.replace('?', name);
    format!("{} {}", specifier(ty), declarator)
        .trim_end()
        .to_string()
}

fn specifier(ty: &CType) -> String {
    match ty {
        CType::Base(text) => text.clone(),
        CType::Qualified(qualifiers, inner) => {
            format!(
                "{}{}",
                qualifier_prefix(qualifiers),
                specifier(inner).trim_start()
            )
        }
        CType::Pointer(to, _) => specifier(to),
        CType::Array(of, _) => specifier(of),
        CType::Function(ret, ..) => specifier(ret),
    }
}

fn walk_type(
    ty: &CType,
    text: &mut String,
    simple: &mut bool,
    names: &mut Option<&[Option<String>]>,
) {
    match ty {
        CType::Base(_) => {}
        CType::Qualified(_, inner) => walk_type(inner, text, simple, names),
        CType::Pointer(to, qualifiers) => {
            // A pointer operator binds to the whole declarator built so far (and
            // the array/function steps below wrap it in parentheses when it is
            // no longer a bare identifier). Inserting it at the identifier would
            // put the star of a return or element type on the wrong side.
            let star = format!("*{}", qualifier_prefix(qualifiers));
            *text = format!("{star}{text}");
            *simple = false;
            walk_type(to, text, simple, names);
        }
        CType::Array(of, count) => {
            let suffix = format!("[{count}]");
            if *simple {
                text.push_str(&suffix);
            } else {
                *text = format!("({text}){suffix}");
            }
            walk_type(of, text, simple, names);
        }
        CType::Function(ret, parameters, variadic) => {
            // Only the outermost function of a declarator can be named.
            let suffix = format!("({})", parameter_text(parameters, names.take(), *variadic));
            if *simple {
                text.push_str(&suffix);
            } else {
                *text = format!("({text}){suffix}");
            }
            *simple = false;
            walk_type(ret, text, simple, names);
        }
    }
}

fn parameter_text(
    parameters: &[CType],
    names: Option<&[Option<String>]>,
    variadic: bool,
) -> String {
    if parameters.is_empty() {
        return if variadic {
            "...".to_string()
        } else {
            "void".to_string()
        };
    }
    // `f(void)` names an empty list; a recorded name on that `void` is not C.
    if parameters.len() == 1 && is_void(&parameters[0]) {
        return "void".to_string();
    }
    let mut parts: Vec<String> = parameters
        .iter()
        .enumerate()
        .map(|(index, parameter)| {
            let name = names
                .and_then(|names| names.get(index))
                .and_then(|name| name.as_deref())
                .unwrap_or("");
            declare(parameter, name)
        })
        .collect();
    if variadic {
        parts.push("...".to_string());
    }
    parts.join(", ")
}

// ---------------------------------------------------------------------------
// Naming
// ---------------------------------------------------------------------------

/// Encode a source name into an identifier fragment.
fn encode(name: &str) -> String {
    if name.is_empty() {
        return "empty".to_string();
    }
    let mut out = String::with_capacity(name.len());
    for byte in name.as_bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => out.push(*byte as char),
            b'_' => out.push_str("__"),
            _ => {
                let _ = write!(out, "_{byte:02x}");
            }
        }
    }
    out
}

fn unique_name(used: &mut BTreeSet<String>, candidate: &str) -> String {
    if used.insert(candidate.to_string()) {
        return candidate.to_string();
    }
    let mut index = 2u64;
    loop {
        let attempt = format!("{candidate}_{index}");
        if used.insert(attempt.clone()) {
            return attempt;
        }
        index += 1;
    }
}

fn is_c_keyword(name: &str) -> bool {
    matches!(
        name,
        "auto"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "typedef"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "_Alignas"
            | "_Alignof"
            | "_Atomic"
            | "_Bool"
            | "_Complex"
            | "_Generic"
            | "_Imaginary"
            | "_Noreturn"
            | "_Static_assert"
            | "_Thread_local"
            | "asm"
            | "typeof"
    )
}

/// True when the name is a C identifier at all: `struct _IO_FILE` and
/// `__int32_t` are real source names an SDK should keep.
fn is_c_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(byte) if byte == b'_' || byte.is_ascii_alphabetic() => {}
        _ => return false,
    }
    if !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()) {
        return false;
    }
    !is_c_keyword(name)
}

/// True when the name is an identifier C can declare at file scope without
/// stepping on the implementation's reserved forms (`_x`, `__x`).
fn is_spellable_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(byte) if byte.is_ascii_alphabetic() => {}
        _ => return false,
    }
    if !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()) {
        return false;
    }
    !is_c_keyword(name)
}

fn is_plain_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(byte) if byte == b'_' || byte.is_ascii_alphabetic() => {}
        _ => return false,
    }
    if !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()) {
        return false;
    }
    if name.starts_with('_') || name.starts_with("s2c_") {
        return false;
    }
    !is_c_keyword(name)
}

fn field_identifier(original: &str, used: &mut BTreeSet<String>) -> String {
    let candidate = if is_plain_identifier(original) {
        original.to_string()
    } else {
        format!("s2c_f_{}", encode(original))
    };
    unique_name(used, &candidate)
}

/// A parameter name, when the document records one that can be spelled in C.
fn parameter_ident(
    name: Option<&str>,
    used: &mut BTreeSet<String>,
    forbidden: &BTreeSet<String>,
) -> Option<String> {
    let name = name?;
    // An unspellable name, a repeat, or a spelling the declaration uses as a
    // type (`f(Packet *Packet, Packet *other)`) stays abstract: a parameter
    // name is cosmetic and must never hide the type it points at.
    if !is_plain_identifier(name) || forbidden.contains(name) || !used.insert(name.to_string()) {
        return None;
    }
    Some(name.to_string())
}

/// Escape free text for a C comment: JSON quoting removes control characters,
/// and `*/` is defused so a record cannot end the comment early.
/// A C string literal that keeps every byte of `text`.
///
/// `comment_text` defuses `*/` and is therefore wrong for data: the table must
/// carry the document key unchanged.
fn c_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for byte in text.bytes() {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(byte as char),
            other => {
                let _ = write!(out, "\\{other:03o}");
            }
        }
    }
    out.push('"');
    out
}

fn comment_text(text: &str) -> String {
    let quoted = serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_string());
    quoted.replace("*/", "* /")
}

fn line(out: &mut String, args: fmt::Arguments<'_>) {
    let _ = out.write_fmt(args);
    out.push('\n');
}

fn blank(out: &mut String) {
    out.push('\n');
}

// ---------------------------------------------------------------------------
// Layout model
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum MemberKind {
    Ordinary(CType),
    Bits,
    Pad,
    UnionStorage,
}

#[derive(Clone)]
struct LayoutMember {
    identifier: String,
    offset: u64,
    size: u64,
    kind: MemberKind,
    origin: Option<String>,
}

#[derive(Clone)]
struct BitfieldLayout {
    field: String,
    identifier: String,
    offset: u64,
    bit_position: u64,
    bit_length: u64,
    signed: bool,
    is_const: bool,
    is_volatile: bool,
}

struct AggregateLayout {
    kind: CompositeKind,
    size: u64,
    alignment: Option<u64>,
    members: Vec<LayoutMember>,
    bitfields: Vec<BitfieldLayout>,
}

struct AccessorNames {
    get: String,
    set: Option<String>,
}

/// One member as the document records it, before placement.
struct Entry {
    offset: u64,
    size: u64,
    origin: String,
    identifier: String,
    ty: EntryType,
}

enum EntryType {
    Ordinary(CType),
    Bits,
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

struct Generator<'a> {
    doc: &'a IsfDocument,
    pointer_size: u64,
    used: Used,
    identifiers: BTreeSet<String>,
    base_names: BTreeMap<String, String>,
    aggregate_names: BTreeMap<String, String>,
    enum_names: BTreeMap<String, String>,
    alias_names: BTreeMap<String, String>,
    layouts: BTreeMap<String, AggregateLayout>,
    order: Vec<String>,
    accessors: BTreeMap<(String, String), AccessorNames>,
    checks: u64,
    functions: Vec<String>,
    function_names: BTreeMap<String, String>,
    with_addresses: bool,
    view: View,
    image_base: Option<u64>,
    allow_by_value_aggregates: bool,
    /// Identifiers the header itself provides (`<stdint.h>` spellings, the guard
    /// macro); an SDK type name falls back to the prefixed form instead.
    reserved: BTreeSet<String>,
    /// Spellings used as types in emitted declarations, so a parameter name can
    /// never hide one.
    forbidden: BTreeSet<String>,
}

impl<'a> Generator<'a> {
    fn new(
        doc: &'a IsfDocument,
        used: Used,
        functions: Vec<String>,
        with_addresses: bool,
        request_view: View,
        request_by_value: bool,
    ) -> Result<Self> {
        let mut generator = Generator {
            doc,
            pointer_size: doc.metadata.sym2isf.target.pointer_size,
            used,
            identifiers: BTreeSet::new(),
            base_names: BTreeMap::new(),
            aggregate_names: BTreeMap::new(),
            enum_names: BTreeMap::new(),
            alias_names: BTreeMap::new(),
            layouts: BTreeMap::new(),
            order: Vec::new(),
            accessors: BTreeMap::new(),
            checks: 0,
            functions,
            function_names: BTreeMap::new(),
            with_addresses,
            view: request_view,
            image_base: doc.metadata.sym2isf.image_base,
            allow_by_value_aggregates: request_by_value,
            reserved: BTreeSet::new(),
            forbidden: BTreeSet::new(),
        };
        generator.reserve_header_identifiers();
        // Reserving the prototype names first lets a function keep a name that
        // would otherwise look like one of the generated identifiers.
        generator.function_names = generator.assign_function_names();
        generator.assign_type_names();
        generator.forbidden = generator.type_spellings();
        generator.compute_layouts()?;
        generator.order = generator.definition_order()?;
        generator.assign_accessors();
        Ok(generator)
    }

    fn unique(&mut self, candidate: &str) -> String {
        unique_name(&mut self.identifiers, candidate)
    }

    fn is_void_base(&self, name: &str) -> bool {
        self.doc
            .base_types
            .get(name)
            .is_some_and(|base| base.kind == BaseKind::Void)
    }

    /// Names the generated header imports or defines itself.
    ///
    /// An SDK type may legitimately be called `int32_t` or `size_t` in a
    /// document; emitting it under that name would collide with the includes, so
    /// those names are reserved and the encoded form is used instead.
    fn reserve_header_identifiers(&mut self) {
        if self.view != View::Sdk {
            return;
        }
        for name in [
            "int8_t",
            "int16_t",
            "int32_t",
            "int64_t",
            "uint8_t",
            "uint16_t",
            "uint32_t",
            "uint64_t",
            "intptr_t",
            "uintptr_t",
            "size_t",
            "ptrdiff_t",
            "float",
            "double",
            "void",
            "S2C_SDK_H",
            "S2C_LITTLE_ENDIAN",
        ] {
            self.reserved.insert(name.to_string());
        }
    }

    /// Every spelling the emitted declarations may use as a type.
    fn type_spellings(&self) -> BTreeSet<String> {
        if self.view != View::Sdk {
            return BTreeSet::new();
        }
        let mut spellings: BTreeSet<String> = self.reserved.clone();
        for name in self
            .base_names
            .values()
            .chain(self.aggregate_names.values())
            .chain(self.enum_names.values())
            .chain(self.alias_names.values())
            .chain(self.function_names.values())
        {
            spellings.insert(name.clone());
        }
        for size in [1u64, 2, 4, 8] {
            spellings.insert(format!("int{}_t", size * 8));
            spellings.insert(format!("uint{}_t", size * 8));
        }
        spellings
    }

    fn assign_function_names(&mut self) -> BTreeMap<String, String> {
        let mut names = BTreeMap::new();
        for name in self.functions.clone() {
            let spellable = match self.view {
                View::Layout => is_spellable_identifier(&name),
                // A struct member lives in its own scope, so the file-scope
                // reserved forms (`_x`) are fine there.
                View::Sdk => is_c_identifier(&name) && !self.reserved.contains(&name),
            };
            let candidate = if spellable {
                name.clone()
            } else {
                format!("s2c_fn_{}", encode(&name))
            };
            let assigned = self.unique(&candidate);
            names.insert(name, assigned);
        }
        names
    }

    /// The name to try for one declaration.
    ///
    /// The layout view always prefixes (it must never collide with a source
    /// name); the SDK view keeps a name C can spell so the header reads like the
    /// original source, and falls back to the prefixed form.
    fn candidate(&self, name: &str, prefix: &str) -> String {
        match self.view {
            View::Layout => format!("{prefix}{}", encode(name)),
            View::Sdk if is_c_identifier(name) && !self.reserved.contains(name) => name.to_string(),
            View::Sdk => format!("{prefix}{}", encode(name)),
        }
    }

    fn assign_type_names(&mut self) {
        let scalars: Vec<String> = self.used.scalars.iter().cloned().collect();
        for name in scalars {
            if self.is_void_base(&name) {
                continue;
            }
            // The SDK view spells scalars with the standard fixed-width types, so
            // only an opaque unit needs a name there.
            if self.view == View::Sdk && self.doc.base_types[&name].kind != BaseKind::Opaque {
                continue;
            }
            let candidate = self.candidate(&name, "s2c_b_");
            let assigned = self.unique(&candidate);
            self.base_names.insert(name, assigned);
        }

        let mut aggregates: Vec<String> = self
            .used
            .declared
            .iter()
            .chain(self.used.complete.iter())
            .cloned()
            .collect();
        aggregates.sort();
        aggregates.dedup();
        for name in aggregates {
            let prefix = match self.doc.user_types[&name].kind {
                CompositeKind::Struct => "s2c_s_",
                CompositeKind::Union => "s2c_u_",
            };
            let candidate = self.candidate(&name, prefix);
            let assigned = self.unique(&candidate);
            self.aggregate_names.insert(name, assigned);
        }

        let enums: Vec<String> = self.used.enums.iter().cloned().collect();
        for name in enums {
            let candidate = self.candidate(&name, "s2c_e_");
            let assigned = self.unique(&candidate);
            self.enum_names.insert(name, assigned);
        }

        let aliases: Vec<String> = self.used.aliases.iter().cloned().collect();
        for name in aliases {
            let candidate = self.candidate(&name, "s2c_a_");
            let assigned = self.unique(&candidate);
            self.alias_names.insert(name, assigned);
        }
    }

    // -----------------------------------------------------------------------
    // Layout reconstruction
    // -----------------------------------------------------------------------

    fn compute_layouts(&mut self) -> Result<()> {
        let names: Vec<String> = self.used.complete.iter().cloned().collect();
        for name in names {
            let layout = self.build_layout(&name)?;
            self.layouts.insert(name, layout);
        }
        Ok(())
    }

    fn build_layout(&self, name: &str) -> Result<AggregateLayout> {
        let user = &self.doc.user_types[name];
        let mut scope: BTreeSet<String> = BTreeSet::new();
        let mut field_identifiers: BTreeMap<String, String> = BTreeMap::new();
        for field in user.fields.keys() {
            field_identifiers.insert(field.clone(), field_identifier(field, &mut scope));
        }
        let alignment = check_alignment(user.alignment, user.size, name)?;
        let bitfields = self.bitfields(user, &field_identifiers);
        let members = match user.kind {
            CompositeKind::Struct => {
                self.struct_members(name, user, &field_identifiers, &mut scope)?
            }
            CompositeKind::Union => {
                self.union_members(name, user, &field_identifiers, &mut scope)?
            }
        };
        Ok(AggregateLayout {
            kind: user.kind,
            size: user.size,
            alignment,
            members,
            bitfields,
        })
    }

    fn struct_members(
        &self,
        name: &str,
        user: &UserType,
        field_identifiers: &BTreeMap<String, String>,
        scope: &mut BTreeSet<String>,
    ) -> Result<Vec<LayoutMember>> {
        let mut ordinary: Vec<Entry> = Vec::new();
        let mut slices: Vec<(u64, u64, String)> = Vec::new();
        for (field, member) in &user.fields {
            let loc = Loc::Field(name, field);
            match &member.ty {
                TypeRef::Bitfield { ty, .. } => {
                    let storage_name = match &**ty {
                        TypeRef::Base { name, .. } => name,
                        _ => return Err(cg(&loc, "bit-field storage is not a base type")),
                    };
                    let storage = &self.doc.base_types[storage_name];
                    slices.push((member.offset, storage.size, field.clone()));
                }
                other => {
                    let size = type_size(self.doc, other)?.ok_or_else(|| {
                        cg(&loc, "member has no static size and cannot be declared")
                    })?;
                    let ctype = self.ctype(other, &mut Vec::new(), &loc)?;
                    ordinary.push(Entry {
                        offset: member.offset,
                        size,
                        origin: field.clone(),
                        identifier: field_identifiers[field].clone(),
                        ty: EntryType::Ordinary(ctype),
                    });
                }
            }
        }

        // Two positive-size ordinary members must not share a byte.
        for (index, left) in ordinary.iter().enumerate() {
            if left.size == 0 {
                continue;
            }
            for right in ordinary.iter().skip(index + 1) {
                if right.size == 0 {
                    continue;
                }
                if left.offset < right.offset + right.size && right.offset < left.offset + left.size
                {
                    return Err(cg(
                        &Loc::Type(name),
                        format!(
                            "ordinary members `{}` {}..{} and `{}` {}..{} overlap",
                            left.origin,
                            left.offset,
                            left.offset + left.size,
                            right.origin,
                            right.offset,
                            right.offset + right.size
                        ),
                    ));
                }
            }
        }
        // A bit-field storage slice must not share a byte with an ordinary member.
        for (offset, size, origin) in &slices {
            for entry in &ordinary {
                if entry.size == 0 {
                    continue;
                }
                if *offset < entry.offset + entry.size && entry.offset < offset + size {
                    return Err(cg(
                        &Loc::Type(name),
                        format!(
                            "bit-field storage `{origin}` {}..{} overlaps ordinary member `{}` {}..{}",
                            offset,
                            offset + size,
                            entry.origin,
                            entry.offset,
                            entry.offset + entry.size
                        ),
                    ));
                }
            }
        }

        // Overlapping or adjacent storage slices share one byte array.
        slices.sort_by_key(|(offset, size, _)| (*offset, *offset + *size));
        let mut groups: Vec<(u64, u64)> = Vec::new();
        for (offset, size, _) in slices {
            match groups.last_mut() {
                Some((_, end)) if offset <= *end => *end = (*end).max(offset + size),
                _ => groups.push((offset, offset + size)),
            }
        }

        let mut regions: Vec<(u64, bool, Entry)> = Vec::new();
        for entry in ordinary {
            let zero = entry.size == 0;
            regions.push((entry.offset, zero, entry));
        }
        for (start, end) in groups {
            regions.push((
                start,
                false,
                Entry {
                    offset: start,
                    size: end - start,
                    origin: String::new(),
                    identifier: unique_name(scope, &format!("s2c_bits_{start}")),
                    ty: EntryType::Bits,
                },
            ));
        }
        // Same offset: zero-sized declarations first, then the recorded order.
        regions.sort_by_key(|(offset, zero, _)| (*offset, !*zero));

        let mut members: Vec<LayoutMember> = Vec::new();
        let mut cursor = 0u64;
        for (offset, _, entry) in regions {
            if offset > cursor {
                members.push(LayoutMember {
                    identifier: unique_name(scope, &format!("s2c_pad_{cursor}")),
                    offset: cursor,
                    size: offset - cursor,
                    kind: MemberKind::Pad,
                    origin: None,
                });
                cursor = offset;
            }
            if offset < cursor {
                if entry.size == 0 {
                    return Err(cg(
                        &Loc::Type(name),
                        format!(
                            "zero-sized member `{}` at offset {offset} cannot be declared after the bytes up to {cursor}",
                            entry.origin
                        ),
                    ));
                }
                return Err(cg(
                    &Loc::Type(name),
                    format!(
                        "member `{}` at offset {offset} starts inside bytes emitted up to {cursor}",
                        entry.origin
                    ),
                ));
            }
            let origin = match entry.ty {
                EntryType::Bits => None,
                EntryType::Ordinary(_) => Some(entry.origin.clone()),
            };
            members.push(LayoutMember {
                identifier: entry.identifier,
                offset: entry.offset,
                size: entry.size,
                kind: match entry.ty {
                    EntryType::Bits => MemberKind::Bits,
                    EntryType::Ordinary(ctype) => MemberKind::Ordinary(ctype),
                },
                origin,
            });
            cursor += entry.size;
        }
        if cursor > user.size {
            return Err(cg(
                &Loc::Type(name),
                format!(
                    "members occupy {cursor} bytes but the recorded size is {}",
                    user.size
                ),
            ));
        }
        if cursor < user.size {
            members.push(LayoutMember {
                identifier: unique_name(scope, &format!("s2c_pad_{cursor}")),
                offset: cursor,
                size: user.size - cursor,
                kind: MemberKind::Pad,
                origin: None,
            });
        }
        Ok(members)
    }

    fn union_members(
        &self,
        name: &str,
        user: &UserType,
        field_identifiers: &BTreeMap<String, String>,
        scope: &mut BTreeSet<String>,
    ) -> Result<Vec<LayoutMember>> {
        let mut members: Vec<LayoutMember> = Vec::new();
        for (field, member) in &user.fields {
            let loc = Loc::Field(name, field);
            match &member.ty {
                TypeRef::Bitfield { .. } => continue,
                other => {
                    if member.offset != 0 {
                        return Err(cg(
                            &loc,
                            format!(
                                "union member `{field}` is recorded at offset {} instead of 0",
                                member.offset
                            ),
                        ));
                    }
                    let size = type_size(self.doc, other)?.ok_or_else(|| {
                        cg(&loc, "member has no static size and cannot be declared")
                    })?;
                    let ctype = self.ctype(other, &mut Vec::new(), &loc)?;
                    members.push(LayoutMember {
                        identifier: field_identifiers[field].clone(),
                        offset: 0,
                        size,
                        kind: MemberKind::Ordinary(ctype),
                        origin: Some(field.clone()),
                    });
                }
            }
        }
        members.push(LayoutMember {
            identifier: unique_name(scope, "s2c_storage"),
            offset: 0,
            size: user.size,
            kind: MemberKind::UnionStorage,
            origin: None,
        });
        Ok(members)
    }

    fn bitfields(
        &self,
        user: &UserType,
        field_identifiers: &BTreeMap<String, String>,
    ) -> Vec<BitfieldLayout> {
        let mut out = Vec::new();
        for (field, member) in &user.fields {
            let TypeRef::Bitfield {
                bit_length,
                bit_position,
                ty,
                declared_type,
            } = &member.ty
            else {
                continue;
            };
            let storage_name = match &**ty {
                TypeRef::Base { name, .. } => name,
                _ => continue,
            };
            let storage = &self.doc.base_types[storage_name];
            let (is_const, is_volatile) = self.declared_qualifiers(declared_type.as_deref());
            out.push(BitfieldLayout {
                field: field.clone(),
                identifier: field_identifiers[field].clone(),
                offset: member.offset,
                bit_position: *bit_position,
                bit_length: *bit_length,
                signed: storage.signed,
                is_const,
                is_volatile,
            });
        }
        out
    }

    // -----------------------------------------------------------------------
    // Type references
    // -----------------------------------------------------------------------

    fn ctype(&self, ty: &TypeRef, chain: &mut Vec<String>, loc: &Loc<'_>) -> Result<CType> {
        match ty {
            TypeRef::Base { name, qualifiers } => {
                let base = self
                    .doc
                    .base_types
                    .get(name)
                    .ok_or_else(|| cg(loc, format!("missing base type `{name}`")))?;
                let text = if base.kind == BaseKind::Void {
                    "void".to_string()
                } else if self.view == View::Sdk && base.kind != BaseKind::Opaque {
                    self.sdk_scalar(base, name)?
                } else {
                    self.base_names.get(name).cloned().ok_or_else(|| {
                        cg(
                            loc,
                            format!("base type `{name}` is only used as bit-field storage"),
                        )
                    })?
                };
                apply_qualifiers(CType::Base(text), qualifiers, loc)
            }
            TypeRef::Struct { name, qualifiers } | TypeRef::Union { name, qualifiers } => {
                let text = self
                    .aggregate_names
                    .get(name)
                    .cloned()
                    .ok_or_else(|| cg(loc, format!("aggregate `{name}` was not declared")))?;
                apply_qualifiers(CType::Base(text), qualifiers, loc)
            }
            TypeRef::Enum { name, qualifiers } => {
                let text = self
                    .enum_names
                    .get(name)
                    .cloned()
                    .ok_or_else(|| cg(loc, format!("enum `{name}` was not declared")))?;
                apply_qualifiers(CType::Base(text), qualifiers, loc)
            }
            TypeRef::Typedef { name, qualifiers } => {
                if chain.iter().any(|seen| seen == name) {
                    return Err(cg(
                        loc,
                        format!("typedef alias `{name}` never reaches a C type"),
                    ));
                }
                let target = self
                    .doc
                    .typedefs
                    .get(name)
                    .ok_or_else(|| cg(loc, format!("missing typedef `{name}`")))?;
                chain.push(name.clone());
                let expanded = self.ctype(target, chain, loc);
                chain.pop();
                apply_qualifiers(expanded?, qualifiers, loc)
            }
            TypeRef::Pointer {
                subtype,
                size,
                qualifiers,
                ..
            } => {
                let effective = size.unwrap_or(self.pointer_size);
                if effective != self.pointer_size {
                    return Err(cg(
                        loc,
                        format!(
                            "pointer of {effective} bytes does not match the target pointer size {}",
                            self.pointer_size
                        ),
                    ));
                }
                let to = self.ctype(subtype, chain, loc)?;
                if qualifiers.contains(&Qualifier::Restrict) && matches!(to, CType::Function(..)) {
                    return Err(cg(loc, "restrict needs an object pointer, not a function"));
                }
                Ok(CType::Pointer(Box::new(to), qualifiers.clone()))
            }
            TypeRef::Array {
                count,
                subtype,
                qualifiers,
            } => {
                let element = self.ctype(subtype, chain, loc)?;
                if is_void(&element) {
                    return Err(cg(loc, "array of void cannot be declared"));
                }
                if matches!(element, CType::Function(..)) {
                    return Err(cg(loc, "array of function cannot be declared"));
                }
                let element = apply_qualifiers(element, qualifiers, loc)?;
                Ok(CType::Array(Box::new(element), *count))
            }
            TypeRef::Bitfield { .. } => Err(cg(loc, "bit-field used as an ordinary type")),
            TypeRef::Function {
                return_type,
                parameters,
                variadic,
                qualifiers,
                ..
            } => {
                let (ret, rendered, variadic) = self.signature_parts(
                    return_type,
                    parameters,
                    *variadic,
                    qualifiers,
                    chain,
                    loc,
                )?;
                Ok(CType::Function(Box::new(ret), rendered, variadic))
            }
        }
    }

    /// Lower one function signature: the C return type, the C parameter types and
    /// whether the declaration is variadic.
    #[allow(clippy::too_many_arguments)]
    fn signature_parts(
        &self,
        return_type: &TypeRef,
        parameters: &[Parameter],
        variadic: Option<bool>,
        qualifiers: &[Qualifier],
        chain: &mut Vec<String>,
        loc: &Loc<'_>,
    ) -> Result<(CType, Vec<CType>, bool)> {
        if !qualifiers.is_empty() {
            return Err(cg(loc, "a function type cannot be qualified"));
        }
        let ret = self.ctype(return_type, chain, loc)?;
        if matches!(ret, CType::Function(..)) {
            return Err(cg(loc, "function returns a function type"));
        }
        if matches!(ret, CType::Array(..)) {
            return Err(cg(loc, "function returns an array type"));
        }
        let mut rendered = Vec::with_capacity(parameters.len());
        for parameter in parameters {
            rendered.push(self.ctype(&parameter.ty, chain, loc)?);
        }
        let variadic = variadic == Some(true);
        if variadic && rendered.is_empty() {
            return Err(cg(
                loc,
                "a variadic function needs at least one fixed parameter",
            ));
        }
        // `f(void)` names an empty list; `void` anywhere else is not C.
        let voids = rendered
            .iter()
            .filter(|parameter| is_void(parameter))
            .count();
        if voids > 0 && (voids != 1 || rendered.len() != 1 || variadic) {
            return Err(cg(
                loc,
                "void is only valid as the sole parameter of a prototype",
            ));
        }
        Ok((ret, rendered, variadic))
    }

    fn declared_qualifiers(&self, declared: Option<&TypeRef>) -> (bool, bool) {
        let mut is_const = false;
        let mut is_volatile = false;
        let mut current = declared;
        // A qualifier may sit on any reference in the alias chain, so every level
        // contributes and the chain is bounded by the number of aliases.
        let mut budget = self.doc.typedefs.len() + 1;
        while let Some(ty) = current {
            match ty {
                TypeRef::Typedef { name, qualifiers } => {
                    is_const |= qualifiers.contains(&Qualifier::Const);
                    is_volatile |= qualifiers.contains(&Qualifier::Volatile);
                    if budget == 0 {
                        break;
                    }
                    budget -= 1;
                    current = self.doc.typedefs.get(name);
                }
                TypeRef::Base { qualifiers, .. }
                | TypeRef::Struct { qualifiers, .. }
                | TypeRef::Union { qualifiers, .. }
                | TypeRef::Enum { qualifiers, .. }
                | TypeRef::Pointer { qualifiers, .. }
                | TypeRef::Array { qualifiers, .. }
                | TypeRef::Function { qualifiers, .. } => {
                    is_const |= qualifiers.contains(&Qualifier::Const);
                    is_volatile |= qualifiers.contains(&Qualifier::Volatile);
                    break;
                }
                TypeRef::Bitfield { .. } => break,
            }
        }
        (is_const, is_volatile)
    }

    // -----------------------------------------------------------------------
    // Definition order
    // -----------------------------------------------------------------------

    fn definition_order(&self) -> Result<Vec<String>> {
        let mut deps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for name in &self.used.complete {
            let mut set = BTreeSet::new();
            let mut seen: BTreeMap<String, Mode> = BTreeMap::new();
            for field in self.doc.user_types[name].fields.values() {
                self.value_dependencies(&field.ty, Mode::Complete, &mut set, &mut seen);
            }
            deps.insert(name.clone(), set);
        }
        let mut done: BTreeSet<String> = BTreeSet::new();
        let mut order = Vec::with_capacity(deps.len());
        while order.len() < deps.len() {
            let next = deps
                .iter()
                .find(|(name, needs)| {
                    !done.contains(*name) && needs.iter().all(|need| done.contains(need))
                })
                .map(|(name, _)| name.clone());
            match next {
                Some(name) => {
                    done.insert(name.clone());
                    order.push(name);
                }
                None => {
                    let remaining: Vec<String> = deps
                        .keys()
                        .filter(|name| !done.contains(*name))
                        .map(|name| format!("`{name}`"))
                        .collect();
                    return Err(cg(
                        &Loc::Roots,
                        format!("C declaration cycle between {}", remaining.join(", ")),
                    ));
                }
            }
        }
        Ok(order)
    }

    /// Aggregates that must be fully defined before this type can be declared.
    fn value_dependencies(
        &self,
        ty: &TypeRef,
        mode: Mode,
        out: &mut BTreeSet<String>,
        seen: &mut BTreeMap<String, Mode>,
    ) {
        match ty {
            TypeRef::Struct { name, .. } | TypeRef::Union { name, .. } => {
                if mode == Mode::Complete && self.used.complete.contains(name) {
                    out.insert(name.clone());
                }
            }
            TypeRef::Typedef { name, .. } => {
                // The same alias can be reached first through a pointer and later
                // by value; only the stronger visit may be skipped.
                if seen.get(name).is_some_and(|visited| *visited >= mode) {
                    return;
                }
                seen.insert(name.clone(), mode);
                if let Some(target) = self.doc.typedefs.get(name) {
                    self.value_dependencies(target, mode, out, seen);
                }
            }
            TypeRef::Pointer { subtype, .. } => {
                self.value_dependencies(subtype, Mode::Declare, out, seen);
            }
            TypeRef::Array { subtype, .. } => {
                self.value_dependencies(subtype, Mode::Complete, out, seen);
            }
            TypeRef::Function {
                return_type,
                parameters,
                ..
            } => {
                // A prototype is a declaration, but an array inside it still needs
                // its element type defined.
                self.value_dependencies(return_type, Mode::Declare, out, seen);
                for parameter in parameters {
                    self.value_dependencies(&parameter.ty, Mode::Declare, out, seen);
                }
            }
            _ => {}
        }
    }

    fn assign_accessors(&mut self) {
        let mut candidates: Vec<(String, String, String, String, bool)> = Vec::new();
        for aggregate in &self.order {
            let layout = &self.layouts[aggregate];
            for bitfield in &layout.bitfields {
                let identifier = &bitfield.identifier;
                candidates.push((
                    aggregate.clone(),
                    bitfield.field.clone(),
                    format!("{}_get_{identifier}", self.aggregate_names[aggregate]),
                    format!("{}_set_{identifier}", self.aggregate_names[aggregate]),
                    bitfield.is_const,
                ));
            }
        }
        for (aggregate, field, get, set, is_const) in candidates {
            let get = self.unique(&get);
            let set = if is_const {
                None
            } else {
                Some(self.unique(&set))
            };
            self.accessors
                .insert((aggregate, field), AccessorNames { get, set });
        }
    }

    // -----------------------------------------------------------------------
    // Emission
    // -----------------------------------------------------------------------

    fn emit(mut self) -> Result<String> {
        let mut out = String::new();
        if self.view == View::Sdk {
            line(&mut out, format_args!("#ifndef S2C_SDK_H"));
            line(&mut out, format_args!("#define S2C_SDK_H"));
            blank(&mut out);
        }
        self.emit_header(&mut out);
        self.emit_forwards(&mut out);
        self.emit_scalars(&mut out)?;
        self.emit_aggregates(&mut out)?;
        self.emit_aliases(&mut out)?;
        match self.view {
            View::Layout => {
                self.emit_prototypes(&mut out)?;
                self.emit_addresses(&mut out)?;
            }
            View::Sdk => self.emit_api(&mut out)?,
        }
        self.emit_assertions(&mut out)?;
        self.emit_accessors(&mut out)?;
        if self.view == View::Sdk {
            line(&mut out, format_args!("#endif /* S2C_SDK_H */"));
        }
        Ok(out)
    }

    fn emit_header(&mut self, out: &mut String) {
        let target = &self.doc.metadata.sym2isf.target;
        let architecture = comment_text(&target.architecture);
        let pointer_size = target.pointer_size;
        line(
            out,
            format_args!(
                "/* generated by sym2isf: {} view of an extended ISF document */",
                match self.view {
                    View::Layout => "layout",
                    View::Sdk => "SDK",
                }
            ),
        );
        line(
            out,
            format_args!("/* target {architecture}: little endian, {pointer_size}-byte pointers;"),
        );
        line(
            out,
            format_args!(" * packed layout: explicit padding, no ABI or alignment promise */"),
        );
        blank(out);
        line(out, format_args!("#include <limits.h>"));
        line(out, format_args!("#include <stddef.h>"));
        line(out, format_args!("#include <stdint.h>"));
        blank(out);
        line(
            out,
            format_args!(
                "#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)"
            ),
        );
        line(
            out,
            format_args!("#error \"s2c: little-endian compiler required\""),
        );
        line(
            out,
            format_args!(
                "#elif !(defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))"
            ),
        );
        line(
            out,
            format_args!(
                "# if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64) || defined(_WIN32)"
            ),
        );
        line(out, format_args!("#  define S2C_LITTLE_ENDIAN 1"));
        line(out, format_args!("# else"));
        line(
            out,
            format_args!("#  error \"s2c: compiler byte order cannot be verified\""),
        );
        line(out, format_args!("# endif"));
        line(out, format_args!("#endif"));
        blank(out);
        self.check(out, "CHAR_BIT == 8");
        self.check(out, &format!("sizeof(void *) == {pointer_size}"));
    }

    fn emit_forwards(&self, out: &mut String) {
        let mut names: Vec<&String> = self
            .used
            .declared
            .iter()
            .chain(self.used.complete.iter())
            .collect();
        names.sort();
        names.dedup();
        if names.is_empty() {
            return;
        }
        line(
            out,
            format_args!("/* aggregate tags, declared before any use */"),
        );
        for name in names {
            let identifier = &self.aggregate_names[name];
            let tag = match self.doc.user_types[name].kind {
                CompositeKind::Struct => "struct",
                CompositeKind::Union => "union",
            };
            line(
                out,
                format_args!("typedef {tag} {identifier} {identifier};"),
            );
        }
        blank(out);
    }

    fn emit_scalars(&mut self, out: &mut String) -> Result<()> {
        let names: Vec<String> = self.used.scalars.iter().cloned().collect();
        for name in names {
            if self.is_void_base(&name) {
                continue;
            }
            let base = &self.doc.base_types[&name];
            if self.view == View::Sdk && base.kind != BaseKind::Opaque {
                // No typedef is emitted for a scalar, but a selected unit is
                // still validated: a width, endian or alignment the SDK cannot
                // spell must fail instead of being silently skipped.
                let _ = self.sdk_scalar(base, &name)?;
                continue;
            }
            let identifier = self.base_names[&name].clone();
            let alignment = check_alignment(base.alignment, base.size, &name)?;
            let attribute = alignment
                .map(|value| format!(" __attribute__((aligned({value})))"))
                .unwrap_or_default();
            if base.kind == BaseKind::Opaque {
                let reason = base
                    .unsupported_reason
                    .as_deref()
                    .unwrap_or("not representable");
                let reason = comment_text(reason);
                let name_text = comment_text(&name);
                line(
                    out,
                    format_args!("/* base type {name_text} is a byte blob: {reason} */"),
                );
                // The layout view keeps its historical anonymous struct; the SDK
                // view names the tag so `struct Name` works as well as `Name`.
                if self.view == View::Sdk {
                    line(
                        out,
                        format_args!(
                            "typedef struct {identifier} {{ unsigned char bytes[{}]; }} {identifier}{attribute};",
                            base.size
                        ),
                    );
                } else {
                    line(
                        out,
                        format_args!(
                            "typedef struct {{ unsigned char s2c_storage[{}]; }} {identifier}{attribute};",
                            base.size
                        ),
                    );
                }
            } else {
                let text = self.scalar_text(&name)?;
                let name_text = comment_text(&name);
                line(
                    out,
                    format_args!("/* base type {name_text} -> {identifier} */"),
                );
                line(out, format_args!("typedef {text} {identifier}{attribute};"));
            }
        }

        let enums: Vec<String> = self.used.enums.iter().cloned().collect();
        for name in enums {
            self.emit_enum(&name, out)?;
        }
        blank(out);
        Ok(())
    }

    /// The standard C spelling of a base unit in the SDK view.
    ///
    /// The layout view needs a named typedef so the type name is stable and
    /// unique; an SDK header reads better with `int32_t` directly.
    fn sdk_scalar(&self, base: &BaseType, name: &str) -> Result<String> {
        let loc = Loc::Type(name);
        if base.endian.is_big() {
            return Err(cg(
                &loc,
                "big-endian scalars cannot be described as little-endian C objects",
            ));
        }
        // A recorded alignment cannot be spelled on a standard scalar type, and
        // silently dropping it would change the type the SDK promises.
        if check_alignment(base.alignment, base.size, name)?.is_some() {
            return Err(cg(
                &loc,
                "an explicitly aligned scalar cannot be spelled with the standard C types",
            ));
        }
        match base.kind {
            BaseKind::Opaque => Err(cg(&loc, "opaque base type is not a scalar")),
            BaseKind::Void => Ok("void".to_string()),
            BaseKind::Float => match base.size {
                4 => Ok("float".to_string()),
                8 => Ok("double".to_string()),
                other => Err(cg(
                    &loc,
                    format!("floating point width {other} bytes has no C type"),
                )),
            },
            BaseKind::Pointer => {
                if base.size != self.pointer_size {
                    return Err(cg(
                        &loc,
                        format!(
                            "pointer unit is {} bytes but the target pointer is {} bytes",
                            base.size, self.pointer_size
                        ),
                    ));
                }
                Ok("uintptr_t".to_string())
            }
            // A character unit keeps a character spelling (`int8_t` is a distinct
            // type from `char`). A frontend that normalizes `char` to a 1-byte
            // integer still spells `int8_t`: the record no longer distinguishes
            // `char` from `signed char`, and the storage is identical.
            BaseKind::Char if base.size == 1 => Ok(if base.signed {
                "char".to_string()
            } else {
                "unsigned char".to_string()
            }),
            BaseKind::Bool | BaseKind::Char | BaseKind::Int => {
                if !matches!(base.size, 1 | 2 | 4 | 8) {
                    return Err(cg(
                        &loc,
                        format!("scalar width {} bytes has no fixed-width C type", base.size),
                    ));
                }
                let bits = base.size * 8;
                Ok(format!(
                    "{}{bits}_t",
                    if base.signed { "int" } else { "uint" }
                ))
            }
        }
    }

    fn scalar_text(&self, name: &str) -> Result<String> {
        let base = &self.doc.base_types[name];
        if base.endian.is_big() {
            return Err(cg(
                &Loc::Type(name),
                "big-endian scalars cannot be described as little-endian C objects",
            ));
        }
        match base.kind {
            BaseKind::Void => Ok("void".to_string()),
            BaseKind::Opaque => Err(cg(&Loc::Type(name), "opaque base type is not a scalar")),
            BaseKind::Float => match base.size {
                4 => Ok("float".to_string()),
                8 => Ok("double".to_string()),
                other => Err(cg(
                    &Loc::Type(name),
                    format!("floating point width {other} bytes has no C type"),
                )),
            },
            BaseKind::Bool | BaseKind::Char | BaseKind::Int | BaseKind::Pointer => {
                if !matches!(base.size, 1 | 2 | 4 | 8) {
                    return Err(cg(
                        &Loc::Type(name),
                        format!("scalar width {} bytes has no fixed-width C type", base.size),
                    ));
                }
                // Only now is the width small enough to multiply safely.
                let bits = base.size * 8;
                Ok(format!(
                    "{}{bits}_t",
                    if base.signed { "int" } else { "uint" }
                ))
            }
        }
    }

    fn emit_enum(&mut self, name: &str, out: &mut String) -> Result<()> {
        let enum_type = &self.doc.enums[name];
        let identifier = self.enum_names[name].clone();
        let loc = Loc::Type(name);
        let signed = match &enum_type.base {
            Some(base_name) => {
                let base = &self.doc.base_types[base_name];
                if base.endian.is_big() {
                    return Err(cg(&loc, format!("enum base `{base_name}` is big-endian")));
                }
                if base.size != enum_type.size {
                    return Err(cg(
                        &loc,
                        format!(
                            "enum size {} disagrees with base `{base_name}` size {}",
                            enum_type.size, base.size
                        ),
                    ));
                }
                base.signed
            }
            None => enum_type
                .constants
                .values()
                .any(|value| value.is_negative()),
        };
        if !matches!(enum_type.size, 1 | 2 | 4 | 8) {
            return Err(cg(
                &loc,
                format!(
                    "enum width {} bytes has no fixed-width C type",
                    enum_type.size
                ),
            ));
        }
        let bits = enum_type.size * 8;
        let name_text = comment_text(name);
        line(out, format_args!("/* enum {name_text} -> {identifier} */"));
        line(
            out,
            format_args!(
                "typedef {}{bits}_t {identifier};",
                if signed { "int" } else { "uint" }
            ),
        );
        let constants: Vec<(String, IntValue)> = enum_type
            .constants
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .collect();
        for (constant, value) in constants {
            let macro_name = self.unique(&format!("{identifier}_{}", encode(&constant)));
            let constant_text = comment_text(&constant);
            line(
                out,
                format_args!("/* constant {constant_text} -> {macro_name} */"),
            );
            line(
                out,
                format_args!(
                    "#define {macro_name} (({identifier}){})",
                    enum_literal(value)
                ),
            );
        }
        Ok(())
    }

    fn emit_aggregates(&self, out: &mut String) -> Result<()> {
        for name in &self.order {
            let layout = &self.layouts[name];
            let identifier = &self.aggregate_names[name];
            let keyword = match layout.kind {
                CompositeKind::Struct => "struct",
                CompositeKind::Union => "union",
            };
            let name_text = comment_text(name);
            line(
                out,
                format_args!("/* user type {name_text} -> {identifier} */"),
            );
            line(out, format_args!("#pragma pack(push, 1)"));
            line(out, format_args!("{keyword} {identifier} {{"));
            for member in &layout.members {
                let text = match &member.kind {
                    MemberKind::Ordinary(ctype) => declare(ctype, &member.identifier),
                    MemberKind::Bits | MemberKind::Pad | MemberKind::UnionStorage => {
                        format!("unsigned char {}[{}]", member.identifier, member.size)
                    }
                };
                let note = match (&member.kind, &member.origin) {
                    (MemberKind::Ordinary(_), Some(origin)) => {
                        format!("field {} -> {}", comment_text(origin), member.identifier)
                    }
                    (MemberKind::Ordinary(_), None) => "member".to_string(),
                    (MemberKind::Bits, _) => "bit-field storage".to_string(),
                    (MemberKind::Pad, _) => "padding".to_string(),
                    (MemberKind::UnionStorage, _) => "union tail".to_string(),
                };
                line(out, format_args!("    {text}; /* {note} */"));
            }
            let attribute = layout
                .alignment
                .map(|value| format!(" __attribute__((aligned({value})))"))
                .unwrap_or_default();
            line(out, format_args!("}}{attribute};"));
            line(out, format_args!("#pragma pack(pop)"));
            blank(out);
        }
        Ok(())
    }

    fn emit_aliases(&self, out: &mut String) -> Result<()> {
        let names: Vec<String> = self.used.aliases.iter().cloned().collect();
        for name in names {
            let loc = Loc::Type(&name);
            let target = &self.doc.typedefs[&name];
            let ctype = self.ctype(target, &mut Vec::new(), &loc)?;
            let identifier = &self.alias_names[&name];
            let declaration = declare(&ctype, identifier);
            // `typedef int32_t int32_t;` declares nothing: the source alias
            // already uses the spelling the expansion produces.
            let parts: Vec<&str> = declaration.split_whitespace().collect();
            if parts.len() == 2 && parts[0] == identifier && parts[1] == identifier {
                continue;
            }
            let name_text = comment_text(&name);
            line(out, format_args!("/* alias {name_text} -> {identifier} */"));
            line(out, format_args!("typedef {declaration};"));
        }
        blank(out);
        Ok(())
    }

    fn emit_prototypes(&mut self, out: &mut String) -> Result<()> {
        if self.view != View::Layout || self.functions.is_empty() {
            return Ok(());
        }
        line(
            out,
            format_args!("/* function signatures: declarations only, no address binding */"),
        );
        for name in self.functions.clone() {
            let function: IsfFunction = self.doc.functions[&name].clone();
            let loc = Loc::Function(&name);
            let mut scope: BTreeSet<String> = BTreeSet::new();
            let names: Vec<Option<String>> = function
                .parameters
                .iter()
                .map(|parameter| {
                    parameter_ident(parameter.name.as_deref(), &mut scope, &self.forbidden)
                })
                .collect();
            let (ret, parameters, variadic) = self.signature_parts(
                &function.return_type,
                &function.parameters,
                function.variadic,
                &[],
                &mut Vec::new(),
                &loc,
            )?;
            // The whole declarator is rendered at once, so a function returning a
            // pointer to a function or to an array keeps C's parentheses right.
            let signature = CType::Function(Box::new(ret), parameters, variadic);
            let identifier = self.function_names[&name].clone();
            let declaration = declare_with_names(&signature, &identifier, Some(&names));
            line(out, format_args!("/* function {} */", comment_text(&name)));
            line(out, format_args!("extern {declaration};"));
        }
        blank(out);
        Ok(())
    }

    /// Reject a signature the ABI-correct call path cannot express.
    fn check_callable(&self, function: &IsfFunction, loc: &Loc<'_>) -> Result<()> {
        // x86-64 has one integer/SSE convention; a 32-bit target has several and
        // the attribute for them is not emitted yet.
        if self.pointer_size == 4 {
            if let Some(convention) = &function.calling_convention {
                if !matches!(convention.as_str(), "near_cdecl" | "cdecl" | "none") {
                    return Err(cg(
                        loc,
                        format!("calling convention `{convention}` is not supported yet"),
                    ));
                }
            }
        }
        if !self.allow_by_value_aggregates {
            if let Some(aggregate) = self.by_value_aggregate(&function.return_type, 0) {
                return Err(cg(
                    loc,
                    format!(
                        "returns aggregate `{aggregate}` by value; pass it by pointer or allow by-value aggregates"
                    ),
                ));
            }
            for parameter in &function.parameters {
                if let Some(aggregate) = self.by_value_aggregate(&parameter.ty, 0) {
                    return Err(cg(
                        loc,
                        format!(
                            "takes aggregate `{aggregate}` by value; pass it by pointer or allow by-value aggregates"
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    /// The aggregate a reference passes by value, if any. An array parameter
    /// decays to a pointer, so its element type is not passed by value.
    fn by_value_aggregate(&self, ty: &TypeRef, depth: usize) -> Option<String> {
        if depth > self.doc.typedefs.len() + 1 {
            return None;
        }
        match ty {
            TypeRef::Struct { name, .. } | TypeRef::Union { name, .. } => Some(name.clone()),
            // An opaque unit is published as a struct, so passing it by value is
            // the same unproven ABI assumption.
            TypeRef::Base { name, .. } => self
                .doc
                .base_types
                .get(name)
                .filter(|base| base.kind == BaseKind::Opaque)
                .map(|_| name.clone()),
            TypeRef::Typedef { name, .. } => self
                .doc
                .typedefs
                .get(name)
                .and_then(|target| self.by_value_aggregate(target, depth + 1)),
            _ => None,
        }
    }

    /// `struct s2c_api` of function pointers plus the binder that fills it.
    ///
    /// Nothing is linked: every member is looked up through the caller's
    /// resolver by source name and recorded offset, so the header works for a
    /// module at any load address.
    fn emit_api(&mut self, out: &mut String) -> Result<()> {
        if self.view != View::Sdk {
            return Ok(());
        }
        if self.functions.is_empty() {
            return Err(cg(
                &Loc::Functions,
                "the SDK view needs at least one selected function",
            ));
        }
        struct Member {
            source: String,
            identifier: String,
            declaration: String,
            cast: String,
            rva: u64,
        }
        let mut members: Vec<Member> = Vec::with_capacity(self.functions.len());
        for name in self.functions.clone() {
            let function: IsfFunction = self.doc.functions[&name].clone();
            let loc = Loc::Function(&name);
            self.check_callable(&function, &loc)?;
            let (ret, parameters, variadic) = self.signature_parts(
                &function.return_type,
                &function.parameters,
                function.variadic,
                &[],
                &mut Vec::new(),
                &loc,
            )?;
            let pointer = CType::Pointer(
                Box::new(CType::Function(Box::new(ret), parameters, variadic)),
                Vec::new(),
            );
            let identifier = self.function_names[&name].clone();
            // The member renders like the source prototype, parameter names
            // included, so the API reads like the original header.
            let mut scope: BTreeSet<String> = BTreeSet::new();
            let names: Vec<Option<String>> = function
                .parameters
                .iter()
                .map(|parameter| {
                    parameter_ident(parameter.name.as_deref(), &mut scope, &self.forbidden)
                })
                .collect();
            let address = function
                .address
                .ok_or_else(|| cg(&loc, "no recorded address"))?;
            let rva = match self.image_base {
                Some(base) if address >= base => address - base,
                Some(base) => {
                    return Err(cg(
                        &loc,
                        format!("address {address:#x} is below image base {base:#x}"),
                    ));
                }
                None => address,
            };
            members.push(Member {
                source: name.clone(),
                declaration: declare_with_names(&pointer, &identifier, Some(&names)),
                cast: declare(&pointer, ""),
                identifier,
                rva,
            });
        }

        let record = self.unique("s2c_api");
        line(
            out,
            format_args!("/* every callable entry point, resolved at run time */"),
        );
        line(out, format_args!("struct {record} {{"));
        for member in &members {
            line(
                out,
                format_args!("    {}; /* {} */", member.declaration, member.identifier),
            );
        }
        line(out, format_args!("}};"));
        line(out, format_args!("typedef struct {record} {record};"));
        blank(out);
        // Resolution is the caller's business: the header only states what it
        // needs (the source name and the recorded offset) and binds what the
        // callback returns. It never computes a module address itself.
        let entry = self.unique("s2c_entry");
        let resolver = self.unique("s2c_resolver");
        line(
            out,
            format_args!("/* one callable address, and the caller's resolver */"),
        );
        line(out, format_args!("typedef void (*{entry})(void);"));
        line(
            out,
            format_args!("typedef {entry} (*{resolver})(const char *name, uintptr_t offset);"),
        );
        blank(out);
        let bind = self.unique("s2c_bind");
        // Allocated, not spelled literally: a document may name a type `api` or
        // `resolve`, and a parameter would hide it inside the binder.
        let api_parameter = self.unique("api");
        let resolve_parameter = self.unique("resolve");
        line(
            out,
            format_args!("/* a NULL result leaves the member NULL; the binder never calls it */"),
        );
        line(
            out,
            format_args!(
                "static inline void {bind}(struct {record} *{api_parameter}, {resolver} {resolve_parameter})"
            ),
        );
        line(out, format_args!("{{"));
        for member in &members {
            let constant = if self.pointer_size == 8 {
                format!("0x{:016x}ULL", member.rva)
            } else {
                format!("0x{:08x}U", member.rva)
            };
            line(
                out,
                format_args!(
                    "    {api_parameter}->{} = ({}) {resolve_parameter}({}, (uintptr_t){constant});",
                    member.identifier,
                    member.cast,
                    c_string(&member.source)
                ),
            );
        }
        line(out, format_args!("}}"));
        blank(out);
        Ok(())
    }

    fn emit_addresses(&mut self, out: &mut String) -> Result<()> {
        if !self.with_addresses {
            return Ok(());
        }
        let mut recorded: Vec<(String, u64)> = Vec::new();
        let mut missing: Vec<String> = Vec::new();
        for name in &self.functions {
            match self.doc.functions[name].address {
                Some(address) => recorded.push((name.clone(), address)),
                None => missing.push(name.clone()),
            }
        }
        if recorded.is_empty() {
            return Err(cg(
                &Loc::Functions,
                "no selected function has a recorded address",
            ));
        }
        let record = self.unique("s2c_address");
        let table = self.unique("s2c_addresses");
        line(
            out,
            format_args!("/* recorded addresses: data only, no symbol binding */"),
        );
        line(out, format_args!("struct {record} {{"));
        line(out, format_args!("    const char *name;"));
        line(out, format_args!("    uint64_t address;"));
        line(out, format_args!("}};"));
        line(
            out,
            format_args!("static const struct {record} {table}[] = {{"),
        );
        for (name, address) in &recorded {
            line(
                out,
                format_args!("    {{ {}, 0x{address:016x}ULL }},", c_string(name)),
            );
        }
        line(out, format_args!("}};"));
        for name in &missing {
            line(
                out,
                format_args!("/* function {}: no recorded address */", comment_text(name)),
            );
        }
        blank(out);
        Ok(())
    }

    fn emit_assertions(&mut self, out: &mut String) -> Result<()> {
        let mut conditions: Vec<String> = Vec::new();
        {
            let scalars: Vec<String> = self.used.scalars.iter().cloned().collect();
            for name in scalars {
                if self.is_void_base(&name) {
                    continue;
                }
                let base = &self.doc.base_types[&name];
                // Only the units that got a typedef need an assertion here.
                if self.view == View::Sdk && base.kind != BaseKind::Opaque {
                    continue;
                }
                let identifier = self.base_names[&name].clone();
                conditions.push(format!("sizeof({identifier}) == {}", base.size));
                if let Some(alignment) = check_alignment(base.alignment, base.size, &name)? {
                    conditions.push(format!("__alignof__({identifier}) == {alignment}"));
                }
            }
            let enums: Vec<String> = self.used.enums.iter().cloned().collect();
            for name in enums {
                let size = self.doc.enums[&name].size;
                let identifier = self.enum_names[&name].clone();
                conditions.push(format!("sizeof({identifier}) == {size}"));
            }
            for name in &self.order {
                let layout = &self.layouts[name];
                let identifier = self.aggregate_names[name].clone();
                if let Some(alignment) = layout.alignment {
                    conditions.push(format!("__alignof__({identifier}) == {alignment}"));
                }
                conditions.push(format!("sizeof({identifier}) == {}", layout.size));
                for member in &layout.members {
                    if matches!(member.kind, MemberKind::Pad) {
                        continue;
                    }
                    conditions.push(format!(
                        "offsetof({identifier}, {}) == {}",
                        member.identifier, member.offset
                    ));
                }
            }
        }
        line(
            out,
            format_args!("/* layout assertions: a mismatch fails the compilation */"),
        );
        for condition in conditions {
            self.check(out, &condition);
        }
        blank(out);
        Ok(())
    }

    fn check(&mut self, out: &mut String, condition: &str) {
        self.checks += 1;
        let name = self.unique(&format!("s2c_check_{}", self.checks));
        line(
            out,
            format_args!("typedef char {name}[({condition}) ? 1 : -1];"),
        );
    }

    /// `static inline` in a header (an unused accessor must not warn), `static`
    /// in the compiled layout unit, whose bytes are part of the shipped output.
    fn accessor_linkage(&self) -> &'static str {
        match self.view {
            View::Layout => "static",
            View::Sdk => "static inline",
        }
    }

    fn emit_accessors(&self, out: &mut String) -> Result<()> {
        if self.accessors.is_empty() {
            return Ok(());
        }
        line(
            out,
            format_args!("/* bit-field accessors: exact storage bytes, no ABI bit-field rules */"),
        );
        for aggregate in &self.order {
            let layout = &self.layouts[aggregate];
            for bitfield in &layout.bitfields {
                let Some(names) = self
                    .accessors
                    .get(&(aggregate.clone(), bitfield.field.clone()))
                else {
                    return Err(cg(
                        &Loc::Field(aggregate, &bitfield.field),
                        "bit-field accessor was not planned",
                    ));
                };
                self.emit_getter(out, aggregate, bitfield, &names.get);
                if let Some(set) = &names.set {
                    self.emit_setter(out, aggregate, bitfield, set);
                }
            }
        }
        Ok(())
    }

    fn emit_getter(
        &self,
        out: &mut String,
        aggregate: &str,
        bitfield: &BitfieldLayout,
        name: &str,
    ) {
        let aggregate_name = &self.aggregate_names[aggregate];
        let cv = if bitfield.is_volatile {
            "volatile "
        } else {
            ""
        };
        let ret = if bitfield.signed {
            "int64_t"
        } else {
            "uint64_t"
        };
        let linkage = self.accessor_linkage();
        let field_text = comment_text(&bitfield.field);
        line(out, format_args!("/* field {field_text} */"));
        line(
            out,
            format_args!("{linkage} {ret} {name}(const {cv}{aggregate_name} *p)"),
        );
        line(out, format_args!("{{"));
        line(
            out,
            format_args!("    const {cv}unsigned char *bytes = (const {cv}unsigned char *)p;"),
        );
        line(out, format_args!("    uint64_t u = 0;"));
        for chunk in bitfield_chunks(bitfield) {
            let read = if chunk.lo == 0 {
                format!("(bytes[{}] & 0x{:02x}U)", chunk.byte, chunk.byte_mask)
            } else {
                format!(
                    "((bytes[{}] >> {}) & 0x{:02x}U)",
                    chunk.byte, chunk.lo, chunk.byte_mask
                )
            };
            line(
                out,
                format_args!("    u |= (uint64_t){read} << {};", chunk.u_shift),
            );
        }
        if bitfield.signed {
            line(
                out,
                format_args!(
                    "    return (u & {}) ? (-1 - (int64_t)({} ^ u)) : (int64_t)u;",
                    sign_bit(bitfield.bit_length),
                    value_mask(bitfield.bit_length)
                ),
            );
        } else {
            line(out, format_args!("    return u;"));
        }
        line(out, format_args!("}}"));
        blank(out);
    }

    fn emit_setter(
        &self,
        out: &mut String,
        aggregate: &str,
        bitfield: &BitfieldLayout,
        name: &str,
    ) {
        let aggregate_name = &self.aggregate_names[aggregate];
        let cv = if bitfield.is_volatile {
            "volatile "
        } else {
            ""
        };
        let argument = if bitfield.signed {
            "int64_t"
        } else {
            "uint64_t"
        };
        let linkage = self.accessor_linkage();
        let field_text = comment_text(&bitfield.field);
        line(out, format_args!("/* field {field_text} (write) */"));
        line(
            out,
            format_args!("{linkage} void {name}({cv}{aggregate_name} *p, {argument} value)"),
        );
        line(out, format_args!("{{"));
        line(
            out,
            format_args!("    {cv}unsigned char *bytes = ({cv}unsigned char *)p;"),
        );
        line(
            out,
            format_args!(
                "    uint64_t u = (uint64_t)value & {};",
                value_mask(bitfield.bit_length)
            ),
        );
        for chunk in bitfield_chunks(bitfield) {
            let keep = !(chunk.byte_mask << chunk.lo) & 0xff;
            let update = if chunk.lo == 0 {
                format!("(u >> {}) & 0x{:02x}U", chunk.u_shift, chunk.byte_mask)
            } else {
                format!(
                    "((u >> {}) & 0x{:02x}U) << {}",
                    chunk.u_shift, chunk.byte_mask, chunk.lo
                )
            };
            line(
                out,
                format_args!(
                    "    bytes[{}] = (unsigned char)((bytes[{}] & 0x{:02x}U) | ({update}));",
                    chunk.byte, chunk.byte, keep
                ),
            );
        }
        line(out, format_args!("}}"));
        blank(out);
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn is_void(ty: &CType) -> bool {
    match ty {
        CType::Base(text) => text == "void",
        CType::Qualified(_, inner) => is_void(inner),
        _ => false,
    }
}

fn apply_qualifiers(ty: CType, qualifiers: &[Qualifier], loc: &Loc<'_>) -> Result<CType> {
    if qualifiers.is_empty() {
        return Ok(ty);
    }
    match ty {
        CType::Base(text) => {
            if qualifiers.contains(&Qualifier::Restrict) {
                return Err(cg(loc, "restrict cannot qualify a non-pointer type"));
            }
            Ok(CType::Qualified(
                merge_qualifiers(&[], qualifiers),
                Box::new(CType::Base(text)),
            ))
        }
        CType::Qualified(existing, inner) => {
            if qualifiers.contains(&Qualifier::Restrict) && !matches!(*inner, CType::Pointer(..)) {
                return Err(cg(loc, "restrict cannot qualify a non-pointer type"));
            }
            Ok(CType::Qualified(
                merge_qualifiers(&existing, qualifiers),
                inner,
            ))
        }
        CType::Pointer(to, existing) => {
            if qualifiers.contains(&Qualifier::Restrict) && matches!(*to, CType::Function(..)) {
                return Err(cg(loc, "restrict needs an object pointer, not a function"));
            }
            Ok(CType::Pointer(to, merge_qualifiers(&existing, qualifiers)))
        }
        CType::Array(of, count) => Ok(CType::Array(
            Box::new(apply_qualifiers(*of, qualifiers, loc)?),
            count,
        )),
        CType::Function(..) => Err(cg(loc, "a function type cannot be qualified")),
    }
}

fn check_alignment(alignment: Option<u64>, size: u64, name: &str) -> Result<Option<u64>> {
    let Some(alignment) = alignment else {
        return Ok(None);
    };
    let loc = Loc::Type(name);
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(cg(
            &loc,
            format!("recorded alignment {alignment} is not a non-zero power of two"),
        ));
    }
    if size % alignment != 0 {
        return Err(cg(
            &loc,
            format!("size {size} is not a multiple of alignment {alignment}"),
        ));
    }
    Ok(Some(alignment))
}

fn enum_literal(value: IntValue) -> String {
    match value {
        IntValue::Unsigned(value) => format!("{value}ULL"),
        IntValue::Signed(value) if value == i64::MIN => {
            "(-9223372036854775807LL - 1LL)".to_string()
        }
        IntValue::Signed(value) => format!("{value}LL"),
    }
}

fn sign_bit(bit_length: u64) -> String {
    if bit_length >= 64 {
        return "0x8000000000000000ULL".to_string();
    }
    format!("0x{:016x}ULL", 1u64 << (bit_length - 1))
}

fn value_mask(bit_length: u64) -> String {
    if bit_length >= 64 {
        return "UINT64_MAX".to_string();
    }
    format!("0x{:016x}ULL", (1u64 << bit_length) - 1)
}

struct Chunk {
    byte: u64,
    lo: u32,
    byte_mask: u32,
    u_shift: u32,
}

/// Split a bit-field range into exactly the bytes it covers.
fn bitfield_chunks(bitfield: &BitfieldLayout) -> Vec<Chunk> {
    // Byte-relative walk: an absolute bit address (`offset * 8 + bit_position`)
    // would overflow for a record whose offset is near `u64::MAX`, even though the
    // field itself fits inside that record.
    let mut byte = bitfield.offset + bitfield.bit_position / 8;
    let mut lo = (bitfield.bit_position % 8) as u32;
    let mut remaining = bitfield.bit_length;
    let mut chunks = Vec::with_capacity((bitfield.bit_length / 8 + 1) as usize);
    while remaining > 0 {
        let width = std::cmp::min(u64::from(8 - lo), remaining) as u32;
        let byte_mask = if width >= 8 {
            0xff
        } else {
            (1u32 << width) - 1
        };
        chunks.push(Chunk {
            byte,
            lo,
            byte_mask,
            u_shift: (bitfield.bit_length - remaining) as u32,
        });
        remaining -= u64::from(width);
        byte += 1;
        lo = 0;
    }
    chunks
}
