//! The extended ISF wire format: document model, validation and writing.
//!
//! The tables and reference shapes follow the Ghidra extended ISF layout used by
//! `Ghidra2ISF.java` (`IsfExporter.typeRef`, `exportComposite`,
//! `exportFunctions`). Everything under `metadata.sym2isf`, plus the `qualifiers`,
//! `size`, `reference_kind`, `declared_type`, `variadic`, `calling_convention`,
//! `alignment`, `incomplete` and `unsupported_reason` members, is an explicit
//! extension of this producer and is never presented as a stock Ghidra field.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// ISF format version emitted in `metadata.format`.
pub const FORMAT_VERSION: &str = "6.2.0";
/// Producer name emitted in `metadata.producer.name`.
pub const PRODUCER_NAME: &str = "sym2isf";
/// Producer version emitted in `metadata.producer.version`.
pub const PRODUCER_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Version of the `metadata.sym2isf` extension block.
pub const EXTENSION_VERSION: u64 = 1;

/// Byte order of the analysed target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

impl Endian {
    /// True for big endian targets.
    pub fn is_big(self) -> bool {
        matches!(self, Endian::Big)
    }

    /// Stable lowercase name.
    pub fn name(self) -> &'static str {
        match self {
            Endian::Little => "little",
            Endian::Big => "big",
        }
    }
}

impl std::fmt::Display for Endian {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Category of a `base_types` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaseKind {
    /// No value; size zero.
    Void,
    /// Boolean.
    Bool,
    /// Character code unit.
    Char,
    /// Floating point.
    Float,
    /// Integer (signed or unsigned).
    Int,
    /// The synthetic unit used for pointer-typed sub-expressions.
    Pointer,
    /// Bytes whose internal structure is not representable statically.
    Opaque,
}

impl BaseKind {
    /// Stable lowercase name.
    pub fn name(self) -> &'static str {
        match self {
            BaseKind::Void => "void",
            BaseKind::Bool => "bool",
            BaseKind::Char => "char",
            BaseKind::Float => "float",
            BaseKind::Int => "int",
            BaseKind::Pointer => "pointer",
            BaseKind::Opaque => "opaque",
        }
    }
}

/// Aggregate category of a `user_types` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompositeKind {
    /// Members laid out one after another.
    Struct,
    /// Members overlapping at offsets recorded in the type.
    Union,
}

impl CompositeKind {
    /// Stable lowercase name.
    pub fn name(self) -> &'static str {
        match self {
            CompositeKind::Struct => "struct",
            CompositeKind::Union => "union",
        }
    }
}

/// Type qualifier carried on a reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Qualifier {
    /// `const`
    Const,
    /// `volatile`
    Volatile,
    /// `restrict`
    Restrict,
}

/// C++ reference flavour recorded for references lowered to pointers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReferenceKind {
    /// `T&`
    Lvalue,
    /// `T&&`
    Rvalue,
}

/// Enum constant value that never truncates to 32 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntValue {
    /// Negative constant.
    Signed(i64),
    /// Non-negative constant.
    Unsigned(u64),
}

impl IntValue {
    /// True when the value is negative.
    pub fn is_negative(self) -> bool {
        matches!(self, IntValue::Signed(v) if v < 0)
    }
}

impl Serialize for IntValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match *self {
            IntValue::Signed(v) => serializer.serialize_i64(v),
            IntValue::Unsigned(v) => serializer.serialize_u64(v),
        }
    }
}

impl<'de> Deserialize<'de> for IntValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Unsigned(u64),
            Signed(i64),
        }
        match Repr::deserialize(deserializer)? {
            Repr::Unsigned(v) => Ok(IntValue::Unsigned(v)),
            Repr::Signed(v) => Ok(IntValue::Signed(v)),
        }
    }
}

/// One parameter of a function signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameter {
    /// Parameter name when the debug information records one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Parameter type.
    #[serde(rename = "type")]
    pub ty: TypeRef,
}

/// A type reference as it appears inside a document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypeRef {
    /// Reference to a `base_types` entry.
    Base {
        /// Table key.
        name: String,
        /// Qualifiers recorded at this reference site.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        qualifiers: Vec<Qualifier>,
    },
    /// Reference to a `user_types` entry of kind `struct`.
    Struct {
        /// Table key.
        name: String,
        /// Qualifiers recorded at this reference site.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        qualifiers: Vec<Qualifier>,
    },
    /// Reference to a `user_types` entry of kind `union`.
    Union {
        /// Table key.
        name: String,
        /// Qualifiers recorded at this reference site.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        qualifiers: Vec<Qualifier>,
    },
    /// Reference to an `enums` entry.
    Enum {
        /// Table key.
        name: String,
        /// Qualifiers recorded at this reference site.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        qualifiers: Vec<Qualifier>,
    },
    /// Reference to a `typedefs` entry.
    Typedef {
        /// Table key.
        name: String,
        /// Qualifiers recorded at this reference site.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        qualifiers: Vec<Qualifier>,
    },
    /// Pointer or reference to another type.
    Pointer {
        /// Pointee type.
        subtype: Box<TypeRef>,
        /// Pointer width override when it differs from the target pointer size.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size: Option<u64>,
        /// Qualifiers recorded at this reference site.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        qualifiers: Vec<Qualifier>,
        /// Set when the source type was a C++ reference.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reference_kind: Option<ReferenceKind>,
    },
    /// Fixed-length array.
    Array {
        /// Element count; zero is preserved for flexible arrays.
        count: u64,
        /// Element type.
        subtype: Box<TypeRef>,
        /// Qualifiers recorded at this reference site.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        qualifiers: Vec<Qualifier>,
    },
    /// Bit-field slice over a synthetic storage unit.
    Bitfield {
        /// Number of value bits.
        bit_length: u64,
        /// Offset of the value bits from the least significant bit of the
        /// storage unit, decoded with the storage unit's own byte order.
        bit_position: u64,
        /// Storage unit; always a `base_types` entry.
        #[serde(rename = "type")]
        ty: Box<TypeRef>,
        /// Declared type of the source bit-field, before normalization.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        declared_type: Option<Box<TypeRef>>,
    },
    /// Function signature, used for function pointers and table entries.
    Function {
        /// Return type.
        return_type: Box<TypeRef>,
        /// Parameters in source order.
        parameters: Vec<Parameter>,
        /// True when the source declares C-style variadic arguments.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        variadic: Option<bool>,
        /// Calling convention name when the source records one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        calling_convention: Option<String>,
        /// Qualifiers recorded at this reference site.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        qualifiers: Vec<Qualifier>,
    },
}

/// One member of a `user_types` entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    /// Byte offset from the start of the containing aggregate.
    pub offset: u64,
    /// Member type.
    #[serde(rename = "type")]
    pub ty: TypeRef,
    /// True when the source member had no name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anonymous: Option<bool>,
}

/// A `base_types` entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseType {
    /// Category of the unit.
    pub kind: BaseKind,
    /// Size in bytes.
    pub size: u64,
    /// True when interpreted as a signed integer.
    pub signed: bool,
    /// Byte order of the unit.
    pub endian: Endian,
    /// Alignment recorded by the debug information, never guessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<u64>,
    /// Why the unit is opaque; present for `kind: "opaque"` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsupported_reason: Option<String>,
}

/// A `user_types` entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserType {
    /// Aggregate category.
    pub kind: CompositeKind,
    /// Size in bytes; zero when the type is only declared.
    pub size: u64,
    /// Members keyed by emitted name.
    pub fields: BTreeMap<String, Field>,
    /// Alignment recorded by the debug information, never guessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<u64>,
    /// True when the debug information only declares this type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incomplete: Option<bool>,
    /// Present only if the document was built by hand; producers emit opaque
    /// aggregates as `base_types` entries instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsupported_reason: Option<String>,
}

/// An `enums` entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumType {
    /// Size in bytes.
    pub size: u64,
    /// Name of the `base_types` entry holding the underlying integer unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// Constants keyed by emitted name.
    pub constants: BTreeMap<String, IntValue>,
}

/// A `symbols` entry: a global object with a statically known address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    /// Address when the debug information gives a static one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    /// Type of the object when known.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub ty: Option<TypeRef>,
}

/// A `functions` entry: a signature, never an executable body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Function {
    /// Address when the debug information gives a static one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    /// Return type.
    pub return_type: TypeRef,
    /// Parameters in source order.
    pub parameters: Vec<Parameter>,
    /// True for C-style variadic functions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variadic: Option<bool>,
    /// Calling convention name when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calling_convention: Option<String>,
}

/// `metadata.producer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Producer {
    /// Producer name.
    pub name: String,
    /// Producer version.
    pub version: String,
}

/// `metadata.sym2isf.target`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// Canonical `object::Architecture` name in lowercase.
    pub architecture: String,
    /// Pointer width in bytes.
    pub pointer_size: u64,
    /// Target byte order.
    pub endian: Endian,
}

/// `metadata.sym2isf`: the producer-specific extension block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sym2IsfMeta {
    /// Version of this extension block.
    pub version: u64,
    /// Target ABI taken from the analysed debug information.
    pub target: Target,
    /// Preferred image base the addresses were formed against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_base: Option<u64>,
}

/// `metadata`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// ISF format version.
    pub format: String,
    /// Producer identification.
    pub producer: Producer,
    /// Producer-specific extension block.
    pub sym2isf: Sym2IsfMeta,
}

/// A complete extended ISF document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsfDocument {
    /// Producer and target metadata.
    pub metadata: Metadata,
    /// Primitive units.
    pub base_types: BTreeMap<String, BaseType>,
    /// Aggregates.
    pub user_types: BTreeMap<String, UserType>,
    /// Enumerations.
    pub enums: BTreeMap<String, EnumType>,
    /// Aliases; the value is the aliased type reference.
    pub typedefs: BTreeMap<String, TypeRef>,
    /// Global objects.
    pub symbols: BTreeMap<String, Symbol>,
    /// Function signatures.
    pub functions: BTreeMap<String, Function>,
}

impl IsfDocument {
    /// An empty document for the given target.
    pub fn empty(target: Target, image_base: Option<u64>) -> Self {
        IsfDocument {
            metadata: Metadata {
                format: FORMAT_VERSION.to_string(),
                producer: Producer {
                    name: PRODUCER_NAME.to_string(),
                    version: PRODUCER_VERSION.to_string(),
                },
                sym2isf: Sym2IsfMeta {
                    version: EXTENSION_VERSION,
                    target,
                    image_base,
                },
            },
            base_types: BTreeMap::new(),
            user_types: BTreeMap::new(),
            enums: BTreeMap::new(),
            typedefs: BTreeMap::new(),
            symbols: BTreeMap::new(),
            functions: BTreeMap::new(),
        }
    }

    /// Check the document against the output contract.
    pub fn validate(&self) -> Result<()> {
        Validator::new(self).run()
    }

    /// Serialize the document as uncompressed JSON after validating it.
    ///
    /// The bytes are a pure function of the document: no timestamps, no host
    /// paths, no hash-map iteration order.
    pub fn to_writer(&self, writer: impl Write) -> Result<()> {
        self.validate()?;
        let mut out = std::io::BufWriter::new(writer);
        serde_json::to_writer_pretty(&mut out, self)?;
        out.write_all(b"\n")
            .map_err(|e| Error::io(PathBuf::from("<writer>"), e))?;
        out.flush()
            .map_err(|e| Error::io(PathBuf::from("<writer>"), e))
    }

    /// Serialize to memory exactly as [`IsfDocument::to_writer`] would.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.to_writer(&mut buf)?;
        Ok(buf)
    }

    /// Validate, serialize, then create `path` and write it.
    ///
    /// The suffix selects the encoding: `.json` stays uncompressed, `.json.xz`
    /// is compressed with a deterministic XZ stream. The file is created with
    /// `create_new`, so an existing output is never overwritten, and a partial
    /// file left by a failed write is removed again.
    pub fn save(&self, path: &Path) -> Result<()> {
        let xz = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) if name.ends_with(".json.xz") => true,
            Some(name) if name.ends_with(".json") => false,
            _ => return Err(Error::UnsupportedOutput { path: path.into() }),
        };
        let json = self.to_vec()?;
        let payload = if xz {
            let mut out = Vec::new();
            let mut cursor = std::io::Cursor::new(&json);
            lzma_rs::xz_compress(&mut cursor, &mut out)
                .map_err(|e| Error::Compression(e.to_string()))?;
            out
        } else {
            json
        };
        let file = match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(Error::OutputExists { path: path.into() });
            }
            Err(e) => return Err(Error::io(path, e)),
        };
        let mut file = file;
        if let Err(e) = file.write_all(&payload).and_then(|()| file.flush()) {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(Error::io(path, e));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DefKey {
    Base(String),
    User(String),
    Enum(String),
    Typedef(String),
}

impl DefKey {
    fn describe(&self) -> String {
        match self {
            DefKey::Base(n) => format!("base type `{n}`"),
            DefKey::User(n) => format!("user type `{n}`"),
            DefKey::Enum(n) => format!("enum `{n}`"),
            DefKey::Typedef(n) => format!("typedef `{n}`"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    InProgress,
    Done,
}

/// Static size of a reference, `None` for `void`, incomplete aggregates and
/// function types.
///
/// This is the single static-size rule shared by the validator and the C
/// generator: pointer-width overrides are honoured, array and aggregate spans are
/// checked, and the remaining alias count bounds alias recursion instead of
/// allocating a visited set.
pub(crate) fn type_size(document: &IsfDocument, reference: &TypeRef) -> Result<Option<u64>> {
    size_of(document, reference, document.typedefs.len())
}

fn size_of(
    document: &IsfDocument,
    reference: &TypeRef,
    aliases_left: usize,
) -> Result<Option<u64>> {
    let pointer_size = document.metadata.sym2isf.target.pointer_size;
    match reference {
        TypeRef::Base { name, .. } => {
            let base = document.base_types.get(name).ok_or_else(|| {
                Error::InvalidDocument(format!("dangling reference to missing base type `{name}`"))
            })?;
            if base.kind == BaseKind::Void {
                Ok(None)
            } else {
                Ok(Some(base.size))
            }
        }
        TypeRef::Struct { name, .. } | TypeRef::Union { name, .. } => {
            let user = document.user_types.get(name).ok_or_else(|| {
                Error::InvalidDocument(format!("dangling reference to missing user type `{name}`"))
            })?;
            if user.incomplete == Some(true) {
                Ok(None)
            } else {
                Ok(Some(user.size))
            }
        }
        TypeRef::Enum { name, .. } => {
            let enum_type = document.enums.get(name).ok_or_else(|| {
                Error::InvalidDocument(format!("dangling reference to missing enum `{name}`"))
            })?;
            Ok(Some(enum_type.size))
        }
        TypeRef::Typedef { name, .. } => {
            if aliases_left == 0 {
                return Err(Error::InvalidDocument(format!(
                    "typedef alias cycle at `{name}`"
                )));
            }
            let target = document.typedefs.get(name).ok_or_else(|| {
                Error::InvalidDocument(format!("dangling reference to missing typedef `{name}`"))
            })?;
            size_of(document, target, aliases_left - 1)
        }
        TypeRef::Pointer { size, .. } => Ok(Some(size.unwrap_or(pointer_size))),
        TypeRef::Array { count, subtype, .. } => {
            if *count == 0 {
                return Ok(Some(0));
            }
            match size_of(document, subtype, aliases_left)? {
                Some(element) => count.checked_mul(element).map(Some).ok_or_else(|| {
                    Error::InvalidDocument(format!(
                        "array span overflows: {count} * {element} bytes"
                    ))
                }),
                None => Err(Error::InvalidDocument(
                    "array element type has no static size".to_string(),
                )),
            }
        }
        TypeRef::Bitfield { ty, .. } => size_of(document, ty, aliases_left),
        TypeRef::Function { .. } => Ok(None),
    }
}

struct Validator<'a> {
    doc: &'a IsfDocument,
    pointer_size: u64,
    states: BTreeMap<DefKey, State>,
    value_states: BTreeMap<DefKey, State>,
}

impl<'a> Validator<'a> {
    fn new(doc: &'a IsfDocument) -> Self {
        Validator {
            doc,
            pointer_size: doc.metadata.sym2isf.target.pointer_size,
            states: BTreeMap::new(),
            value_states: BTreeMap::new(),
        }
    }

    fn invalid(msg: impl Into<String>) -> Error {
        Error::InvalidDocument(msg.into())
    }

    fn run(&mut self) -> Result<()> {
        if self.pointer_size == 0 {
            return Err(Self::invalid("target pointer size must be non-zero"));
        }
        if self.doc.metadata.sym2isf.version != EXTENSION_VERSION {
            return Err(Self::invalid(format!(
                "unsupported metadata.sym2isf.version {}",
                self.doc.metadata.sym2isf.version
            )));
        }
        if self.doc.metadata.format != FORMAT_VERSION {
            return Err(Self::invalid(format!(
                "unsupported metadata.format {:?}",
                self.doc.metadata.format
            )));
        }
        if self.doc.metadata.producer.name != PRODUCER_NAME {
            return Err(Self::invalid(format!(
                "unsupported producer name {:?}",
                self.doc.metadata.producer.name
            )));
        }
        if self.doc.base_types.is_empty() {
            return Err(Self::invalid("base_types must contain at least `void`"));
        }

        let mut keys: Vec<DefKey> = Vec::new();
        keys.extend(self.doc.base_types.keys().cloned().map(DefKey::Base));
        keys.extend(self.doc.user_types.keys().cloned().map(DefKey::User));
        keys.extend(self.doc.enums.keys().cloned().map(DefKey::Enum));
        keys.extend(self.doc.typedefs.keys().cloned().map(DefKey::Typedef));
        for key in keys {
            self.resolve_def(&key)?;
        }

        for name in self.doc.user_types.keys() {
            self.check_aggregate_rules(&DefKey::User(name.clone()))?;
        }

        for (name, symbol) in &self.doc.symbols {
            if let Some(ty) = &symbol.ty {
                self.check_ref(ty)
                    .map_err(|e| Self::context(e, &format!("symbol `{name}`")))?;
            }
        }
        for (name, function) in &self.doc.functions {
            self.check_signature(&function.return_type, &function.parameters)
                .map_err(|e| Self::context(e, &format!("function `{name}`")))?;
        }
        Ok(())
    }

    fn context(error: Error, what: &str) -> Error {
        match error {
            Error::InvalidDocument(msg) => Error::InvalidDocument(format!("{what}: {msg}")),
            other => other,
        }
    }

    fn resolve_def(&mut self, key: &DefKey) -> Result<()> {
        match self.states.get(key) {
            Some(State::Done) => return Ok(()),
            Some(State::InProgress) => return Ok(()),
            None => {}
        }
        self.states.insert(key.clone(), State::InProgress);
        let result = match key {
            DefKey::Base(name) => self.check_base(name),
            DefKey::User(name) => self.check_user(name),
            DefKey::Enum(name) => self.check_enum(name),
            DefKey::Typedef(name) => self.check_typedef(name),
        };
        match result {
            Ok(()) => {
                self.states.insert(key.clone(), State::Done);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn check_base(&self, name: &str) -> Result<()> {
        let base = &self.doc.base_types[name];
        if base.kind == BaseKind::Void && base.size != 0 {
            return Err(Self::invalid(format!(
                "base type `{name}` is void but has size {}",
                base.size
            )));
        }
        if base.kind != BaseKind::Void && base.size == 0 {
            return Err(Self::invalid(format!(
                "base type `{name}` is not void but has size 0"
            )));
        }
        if base.kind == BaseKind::Opaque && base.unsupported_reason.is_none() {
            return Err(Self::invalid(format!(
                "opaque base type `{name}` has no unsupported_reason"
            )));
        }
        if base.kind != BaseKind::Opaque && base.unsupported_reason.is_some() {
            return Err(Self::invalid(format!(
                "base type `{name}` carries an unsupported_reason but is not opaque"
            )));
        }
        Ok(())
    }

    fn check_user(&mut self, name: &str) -> Result<()> {
        let user = &self.doc.user_types[name];
        if user.unsupported_reason.is_some() && user.incomplete != Some(true) {
            return Err(Self::invalid(format!(
                "complete user type `{name}` carries an unsupported_reason; opaque aggregates must be emitted as base types"
            )));
        }
        if user.incomplete == Some(true) && !user.fields.is_empty() {
            return Err(Self::invalid(format!(
                "incomplete user type `{name}` has fields"
            )));
        }
        let fields: Vec<(String, Field)> = user
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (field_name, field) in fields {
            self.check_ref(&field.ty).map_err(|e| {
                Self::context(e, &format!("{} `{name}::{field_name}`", user.kind.name()))
            })?;
        }
        Ok(())
    }

    fn check_enum(&mut self, name: &str) -> Result<()> {
        let enum_type = self.doc.enums[name].clone();
        match &enum_type.base {
            Some(base_name) => {
                let base = self.doc.base_types.get(base_name).ok_or_else(|| {
                    Self::invalid(format!(
                        "enum `{name}` refers to missing base type `{base_name}`"
                    ))
                })?;
                if !matches!(base.kind, BaseKind::Int | BaseKind::Char | BaseKind::Bool) {
                    return Err(Self::invalid(format!(
                        "enum `{name}` has non-integer base `{base_name}` of kind {}",
                        base.kind.name()
                    )));
                }
                if base.size != enum_type.size {
                    return Err(Self::invalid(format!(
                        "enum `{name}` size {} disagrees with base `{base_name}` size {}",
                        enum_type.size, base.size
                    )));
                }
                for (constant, value) in &enum_type.constants {
                    if !fits(*value, base.signed, base.size) {
                        return Err(Self::invalid(format!(
                            "enum constant `{name}::{constant}` = {value:?} does not fit base `{base_name}`"
                        )));
                    }
                }
            }
            None => {
                if enum_type.size == 0 {
                    return Err(Self::invalid(format!(
                        "enum `{name}` has no base and no size"
                    )));
                }
                let signed = enum_type.constants.values().any(|v| v.is_negative());
                for (constant, value) in &enum_type.constants {
                    if !fits(*value, signed, enum_type.size) {
                        return Err(Self::invalid(format!(
                            "enum constant `{name}::{constant}` = {value:?} does not fit {} {}",
                            if signed { "signed" } else { "unsigned" },
                            enum_type.size
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    fn check_typedef(&mut self, name: &str) -> Result<()> {
        // Only a *direct* alias chain can cycle; pointers, arrays and function
        // signatures break the chain and keep the recursion finite.
        let mut chain = vec![name.to_string()];
        let mut current = self.doc.typedefs[name].clone();
        while let TypeRef::Typedef { name: next, .. } = &current {
            if !self.doc.typedefs.contains_key(next) {
                return Err(Self::invalid(format!(
                    "dangling reference to missing typedef `{next}`"
                )));
            }
            if chain.iter().any(|name| name == next) {
                chain.push(next.clone());
                return Err(Self::invalid(format!(
                    "typedef alias cycle: {}",
                    chain.join(" -> ")
                )));
            }
            chain.push(next.clone());
            let next = next.clone();
            current = self.doc.typedefs[&next].clone();
        }
        self.check_ref(&current)
            .map_err(|e| Self::context(e, &format!("typedef `{name}`")))
    }

    fn check_ref(&mut self, reference: &TypeRef) -> Result<()> {
        match reference {
            TypeRef::Base { name, .. } => {
                let key = DefKey::Base(name.clone());
                if !self.doc.base_types.contains_key(name) {
                    return Err(Self::invalid(format!(
                        "dangling reference to missing base type `{name}`"
                    )));
                }
                self.resolve_def(&key)
            }
            TypeRef::Struct { name, .. } => {
                let user = self.doc.user_types.get(name).ok_or_else(|| {
                    Self::invalid(format!("dangling reference to missing struct `{name}`"))
                })?;
                if user.kind != CompositeKind::Struct {
                    return Err(Self::invalid(format!(
                        "struct reference `{name}` resolves to a {}",
                        user.kind.name()
                    )));
                }
                self.resolve_def(&DefKey::User(name.clone()))
            }
            TypeRef::Union { name, .. } => {
                let user = self.doc.user_types.get(name).ok_or_else(|| {
                    Self::invalid(format!("dangling reference to missing union `{name}`"))
                })?;
                if user.kind != CompositeKind::Union {
                    return Err(Self::invalid(format!(
                        "union reference `{name}` resolves to a {}",
                        user.kind.name()
                    )));
                }
                self.resolve_def(&DefKey::User(name.clone()))
            }
            TypeRef::Enum { name, .. } => {
                if !self.doc.enums.contains_key(name) {
                    return Err(Self::invalid(format!(
                        "dangling reference to missing enum `{name}`"
                    )));
                }
                self.resolve_def(&DefKey::Enum(name.clone()))
            }
            TypeRef::Typedef { name, .. } => {
                if !self.doc.typedefs.contains_key(name) {
                    return Err(Self::invalid(format!(
                        "dangling reference to missing typedef `{name}`"
                    )));
                }
                self.resolve_def(&DefKey::Typedef(name.clone()))
            }
            TypeRef::Pointer { subtype, size, .. } => {
                if *size == Some(0) {
                    return Err(Self::invalid("pointer reference has size 0"));
                }
                self.check_ref(subtype)
            }
            TypeRef::Array { count, subtype, .. } => {
                self.check_ref(subtype)?;
                let element = type_size(self.doc, subtype)?.ok_or_else(|| {
                    Self::invalid("array element type has no static size".to_string())
                })?;
                count.checked_mul(element).ok_or_else(|| {
                    Self::invalid(format!("array span overflows: {count} * {element} bytes"))
                })?;
                Ok(())
            }
            TypeRef::Bitfield {
                bit_length,
                bit_position,
                ty,
                declared_type,
            } => {
                if *bit_length == 0 {
                    return Err(Self::invalid("bitfield has zero bit_length"));
                }
                let storage_name = match &**ty {
                    TypeRef::Base { name, .. } => name,
                    _ => {
                        return Err(Self::invalid(
                            "bitfield storage must be a base type reference".to_string(),
                        ));
                    }
                };
                let storage = self.doc.base_types.get(storage_name).ok_or_else(|| {
                    Self::invalid(format!("bitfield storage `{storage_name}` is missing"))
                })?;
                let bits = storage
                    .size
                    .checked_mul(8)
                    .ok_or_else(|| Self::invalid("bitfield storage size overflows".to_string()))?;
                let end = bit_position
                    .checked_add(*bit_length)
                    .ok_or_else(|| Self::invalid("bitfield bit range overflows".to_string()))?;
                if end > bits {
                    return Err(Self::invalid(format!(
                        "bitfield bits {bit_position}..{end} exceed storage `{storage_name}` width {bits}"
                    )));
                }
                if let Some(declared) = declared_type {
                    self.check_ref(declared)?;
                }
                Ok(())
            }
            TypeRef::Function {
                return_type,
                parameters,
                ..
            } => self.check_signature(return_type, parameters),
        }
    }

    fn check_signature(&mut self, return_type: &TypeRef, parameters: &[Parameter]) -> Result<()> {
        if matches!(return_type, TypeRef::Function { .. }) {
            return Err(Self::invalid(
                "function returns a function type by value".to_string(),
            ));
        }
        self.check_ref(return_type)?;
        for parameter in parameters {
            if matches!(parameter.ty, TypeRef::Function { .. }) {
                return Err(Self::invalid(
                    "parameter has a function type by value".to_string(),
                ));
            }
            self.check_ref(&parameter.ty)?;
        }
        Ok(())
    }

    fn is_void(&self, reference: &TypeRef) -> bool {
        match reference {
            TypeRef::Base { name, .. } => self
                .doc
                .base_types
                .get(name)
                .is_some_and(|base| base.kind == BaseKind::Void),
            _ => false,
        }
    }

    fn check_aggregate_rules(&mut self, key: &DefKey) -> Result<()> {
        let name = match key {
            DefKey::User(name) => name.clone(),
            _ => return Ok(()),
        };
        let user = self.doc.user_types[&name].clone();
        let complete = user.incomplete != Some(true);
        for (field_name, field) in &user.fields {
            let size = type_size(self.doc, &field.ty)?;
            match size {
                Some(size) => {
                    let end = field.offset.checked_add(size).ok_or_else(|| {
                        Self::invalid(format!(
                            "{} `{name}::{field_name}` offset {} + size {size} overflows",
                            user.kind.name(),
                            field.offset
                        ))
                    })?;
                    if complete && end > user.size {
                        return Err(Self::invalid(format!(
                            "{} `{name}::{field_name}` spans {}..{end} beyond size {}",
                            user.kind.name(),
                            field.offset,
                            user.size
                        )));
                    }
                }
                None => {
                    if matches!(field.ty, TypeRef::Function { .. }) {
                        return Err(Self::invalid(format!(
                            "`{name}::{field_name}` is a function type by value"
                        )));
                    }
                    if self.is_void(&field.ty) {
                        return Err(Self::invalid(format!(
                            "`{name}::{field_name}` has type void"
                        )));
                    }
                    let incomplete = self.incomplete_kind(&field.ty);
                    return Err(Self::invalid(format!(
                        "`{name}::{field_name}` is a {incomplete} used by value"
                    )));
                }
            }
        }
        if complete {
            self.check_value_cycle(&DefKey::User(name.clone()))?;
        }
        Ok(())
    }

    fn incomplete_kind(&self, reference: &TypeRef) -> String {
        match reference {
            TypeRef::Struct { name, .. } | TypeRef::Union { name, .. } => {
                if self
                    .doc
                    .user_types
                    .get(name)
                    .is_some_and(|u| u.incomplete == Some(true))
                {
                    "incomplete aggregate".to_string()
                } else {
                    "type without static size".to_string()
                }
            }
            TypeRef::Typedef { name, .. } => self
                .doc
                .typedefs
                .get(name)
                .map(|t| self.incomplete_kind(t))
                .unwrap_or_else(|| "type without static size".to_string()),
            TypeRef::Array { subtype, .. } => self.incomplete_kind(subtype),
            TypeRef::Bitfield { ty, .. } => self.incomplete_kind(ty),
            _ => "type without static size".to_string(),
        }
    }

    /// By-value containment cycles (`struct S { S inner; }`, alias loops reached
    /// through aggregates) are rejected; pointer recursion is fine.
    fn check_value_cycle(&mut self, key: &DefKey) -> Result<()> {
        match self.value_states.get(key) {
            Some(State::Done) => return Ok(()),
            Some(State::InProgress) => {
                return Err(Self::invalid(format!(
                    "recursive by-value containment at {}",
                    key.describe()
                )));
            }
            None => {}
        }
        self.value_states.insert(key.clone(), State::InProgress);
        let mut targets = Vec::new();
        match key {
            DefKey::User(name) => {
                if let Some(user) = self.doc.user_types.get(name) {
                    for field in user.fields.values() {
                        self.value_targets(&field.ty, &mut targets);
                    }
                }
            }
            DefKey::Typedef(name) => {
                if let Some(target) = self.doc.typedefs.get(name) {
                    self.value_targets(target, &mut targets);
                }
            }
            _ => {}
        }
        for target in targets {
            self.check_value_cycle(&target)?;
        }
        self.value_states.insert(key.clone(), State::Done);
        Ok(())
    }

    fn value_targets(&self, reference: &TypeRef, out: &mut Vec<DefKey>) {
        match reference {
            TypeRef::Struct { name, .. } => out.push(DefKey::User(name.clone())),
            TypeRef::Union { name, .. } => out.push(DefKey::User(name.clone())),
            TypeRef::Typedef { name, .. } => out.push(DefKey::Typedef(name.clone())),
            TypeRef::Array { subtype, .. } => self.value_targets(subtype, out),
            TypeRef::Bitfield { ty, .. } => self.value_targets(ty, out),
            TypeRef::Base { .. } | TypeRef::Enum { .. } | TypeRef::Pointer { .. } => {}
            TypeRef::Function { .. } => {}
        }
    }
}

/// True when `value` is representable in `size` bytes with the given signedness.
fn fits(value: IntValue, signed: bool, size: u64) -> bool {
    let Some(bits) = size.checked_mul(8) else {
        return false;
    };
    if signed {
        let value = match value {
            IntValue::Signed(v) => v as i128,
            IntValue::Unsigned(v) => v as i128,
        };
        if bits >= 128 {
            return true;
        }
        let bound = 1i128 << (bits - 1);
        value >= -bound && value < bound
    } else {
        let value = match value {
            IntValue::Signed(v) => {
                if v < 0 {
                    return false;
                }
                v as u128
            }
            IntValue::Unsigned(v) => v as u128,
        };
        if bits >= 128 {
            return true;
        }
        value < (1u128 << bits)
    }
}
