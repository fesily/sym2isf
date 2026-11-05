//! Shared normalization between the debug-format frontends and the ISF writer.
//!
//! Frontends never build ISF tables directly. They build a [`TypeGraph`] keyed by
//! stable source record ids, and this module owns everything that must behave
//! identically for DWARF and PDB input:
//!
//! * naming, including conflict suffixes and anonymous names,
//! * structural de-duplication of equivalent definitions,
//! * lowering of qualified types, references and bit-fields to wire references,
//! * conversion of non-representable aggregates to `opaque` base types,
//! * insertion into the fixed output tables.
//!
//! This is deliberately *not* a layout engine: it does not compute offsets, sizes
//! or member placement. Those come from the debug information unchanged.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};
use crate::isf::{
    BaseKind, BaseType, CompositeKind, EnumType, Field, Function as IsfFunction, IntValue,
    IsfDocument, Parameter, Qualifier, ReferenceKind, Symbol, Target, TypeRef, UserType,
};

/// Stable identifier of a node inside a [`TypeGraph`].
pub type TypeId = u32;

/// Where a debug record came from; used for diagnostics and stable name suffixes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    /// A DWARF DIE, identified by its section and absolute offset within it.
    Dwarf {
        /// Section the DIE lives in, for example `.debug_info`.
        section: String,
        /// Absolute offset inside that section.
        offset: u64,
    },
    /// A PDB type record, identified by its `TypeIndex`.
    Pdb {
        /// `TypeIndex` of the record.
        type_index: u32,
    },
    /// A record this frontend had to synthesize.
    Synthetic {
        /// Short description of the synthesized record.
        tag: String,
    },
}

impl Origin {
    /// Stable token used in generated names.
    pub fn token(&self) -> String {
        match self {
            Origin::Dwarf { section, offset } => {
                format!("dwarf_{}_{offset:x}", sanitize_section(section))
            }
            Origin::Pdb { type_index } => format!("pdb_{type_index:x}"),
            Origin::Synthetic { tag } => format!("sym2isf_{}", sanitize_section(tag)),
        }
    }

    /// Human readable location for error messages.
    pub fn location(&self) -> String {
        match self {
            Origin::Dwarf { section, offset } => format!("{section} DIE at {offset:#x}"),
            Origin::Pdb { type_index } => format!("PDB type index {type_index:#x}"),
            Origin::Synthetic { tag } => format!("synthetic record `{tag}`"),
        }
    }
}

fn sanitize_section(section: &str) -> String {
    let trimmed = section.trim_start_matches('.');
    let mut out = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("unknown");
    }
    out
}

/// How a source record named a base unit.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BaseName {
    /// The synthetic `void` unit.
    Void,
    /// The synthetic pointer-sized unit used by pointer sub-expressions.
    Pointer,
    /// A name taken verbatim from the debug information.
    Source(String),
    /// A synthetic storage unit for a normalized bit-field slice.
    BitStorage {
        /// Signedness of the declared bit-field type.
        signed: bool,
        /// Number of whole bytes in the slice.
        bytes: u8,
    },
}

/// A `base_types` record before naming.
#[derive(Clone, Debug)]
pub struct BaseRecord {
    /// Where the name comes from.
    pub name: BaseName,
    /// Size in bytes.
    pub size: u64,
    /// Signedness.
    pub signed: bool,
    /// Unit category.
    pub kind: BaseKind,
    /// Alignment recorded by the debug information.
    pub alignment: Option<u64>,
    /// Set when the unit is opaque.
    pub unsupported_reason: Option<String>,
    /// Where the record came from; kept from the first record that interned it.
    pub origin: Origin,
}

/// A pointer or reference type.
#[derive(Clone, Debug)]
pub struct PointerRecord {
    /// Pointee.
    pub target: TypeId,
    /// Pointer width when the record states one.
    pub size: Option<u64>,
    /// Set when the source type was a C++ reference.
    pub reference_kind: Option<ReferenceKind>,
}

/// A fixed-length array.
#[derive(Clone, Debug)]
pub struct ArrayRecord {
    /// Element type.
    pub element: TypeId,
    /// Element count; zero is preserved.
    pub count: u64,
}

/// A qualifier wrapper around another type.
#[derive(Clone, Debug)]
pub struct QualifiedRecord {
    /// Wrapped type.
    pub target: TypeId,
    /// Applied qualifier.
    pub qualifier: Qualifier,
}

/// One member of an aggregate.
#[derive(Clone, Debug)]
pub struct Member {
    /// Source member name.
    pub name: Option<String>,
    /// Byte offset of the member, or of the bit-field storage slice.
    pub offset: u64,
    /// Declared member type.
    pub ty: TypeId,
    /// Bit-field description when the member is one.
    pub bitfield: Option<BitfieldInfo>,
    /// True when the source member is anonymous.
    pub anonymous: bool,
}

/// Normalized bit-field placement.
#[derive(Clone, Copy, Debug)]
pub struct BitfieldInfo {
    /// Number of value bits.
    pub bit_length: u64,
    /// Offset from the least significant bit of the storage unit.
    pub bit_position: u64,
    /// Synthetic storage base.
    pub storage: TypeId,
}

/// An aggregate record before naming.
#[derive(Clone, Debug)]
pub struct CompositeRecord {
    /// Fully qualified name when the source has one.
    pub name: Option<String>,
    /// Struct or union; `class` is recorded as `struct`.
    pub kind: CompositeKind,
    /// Size in bytes; `None` only for forward declarations.
    pub size: Option<u64>,
    /// Alignment recorded by the debug information.
    pub alignment: Option<u64>,
    /// Members in source order.
    pub members: Vec<Member>,
    /// Name domain the record was defined in (its compilation unit), when the
    /// debug information identifies one.
    pub domain: Option<String>,
    /// Where the record came from.
    pub origin: Origin,
    /// True when the debug information only declares the type.
    pub incomplete: bool,
    /// Why the aggregate cannot be represented statically.
    pub unsupported: Option<String>,
}

/// An enumeration record before naming.
#[derive(Clone, Debug)]
pub struct EnumRecord {
    /// Fully qualified name when the source has one.
    pub name: Option<String>,
    /// Size in bytes.
    pub size: u64,
    /// Underlying integer unit when the source states one.
    pub base: Option<TypeId>,
    /// Constants in source order.
    pub constants: Vec<(String, IntValue)>,
    /// Name domain the record was defined in, when the debug information says so.
    pub domain: Option<String>,
    /// Where the record came from.
    pub origin: Origin,
    /// Why the enumeration cannot be represented statically.
    pub unsupported: Option<String>,
}

/// An alias record.
#[derive(Clone, Debug)]
pub struct TypedefRecord {
    /// Alias name.
    pub name: String,
    /// Aliased type.
    pub target: TypeId,
    /// Name domain the alias was defined in, when the debug information says so.
    pub domain: Option<String>,
    /// Where the record came from.
    pub origin: Origin,
}

/// A function signature.
#[derive(Clone, Debug)]
pub struct FunctionRecord {
    /// Return type.
    pub return_type: TypeId,
    /// Parameters in source order.
    pub parameters: Vec<(Option<String>, TypeId)>,
    /// True for C-style variadic functions.
    pub variadic: bool,
    /// Calling convention name when recorded.
    pub calling_convention: Option<String>,
}

/// A node of the normalized type graph.
#[derive(Clone, Debug)]
pub enum Node {
    /// Primitive unit.
    Base(BaseRecord),
    /// Pointer or reference.
    Pointer(PointerRecord),
    /// Fixed-length array.
    Array(ArrayRecord),
    /// Qualifier wrapper.
    Qualified(QualifiedRecord),
    /// Aggregate.
    Composite(CompositeRecord),
    /// Enumeration.
    Enum(EnumRecord),
    /// Alias.
    Typedef(TypedefRecord),
    /// Function signature.
    Function(FunctionRecord),
}

/// A normalized bit-field slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitfieldSlice {
    /// Byte offset of the sliced storage inside the containing aggregate.
    pub offset: u64,
    /// Number of whole bytes in the storage slice.
    pub storage_bytes: u8,
    /// Offset from the least significant bit of the decoded storage unit.
    pub bit_position: u64,
}

/// Compute the shortest byte slice that covers an address-order bit range.
///
/// `byte_bit_start` is the distance in bits from the start of the containing
/// aggregate to the first bit of the field, in address order. For little endian
/// targets the wire `bit_position` counts from the least significant bit of the
/// decoded byte slice; for big endian targets it is flipped so that both byte
/// orders share one meaning.
pub fn bitfield_slice(
    origin: &Origin,
    byte_bit_start: u64,
    bit_length: u64,
    endian: crate::isf::Endian,
) -> Result<BitfieldSlice> {
    if bit_length == 0 {
        return Err(Error::UnsupportedLayout {
            location: origin.location(),
            detail: "zero-width bit-field must not be emitted as a member".to_string(),
        });
    }
    let offset = byte_bit_start / 8;
    let start_bit = byte_bit_start % 8;
    let span = start_bit
        .checked_add(bit_length)
        .ok_or_else(|| Error::Overflow {
            location: origin.location(),
            what: "bit-field span".to_string(),
        })?;
    let bytes = span.div_ceil(8);
    let storage_bytes = u8::try_from(bytes).map_err(|_| Error::UnsupportedLayout {
        location: origin.location(),
        detail: format!("bit-field storage of {bytes} bytes is too wide to normalize"),
    })?;
    if storage_bytes > 16 {
        return Err(Error::UnsupportedLayout {
            location: origin.location(),
            detail: format!("bit-field storage of {storage_bytes} bytes is too wide to normalize"),
        });
    }
    let bits = u64::from(storage_bytes) * 8;
    let bit_position = if endian.is_big() {
        bits.checked_sub(start_bit + bit_length)
            .ok_or_else(|| Error::Overflow {
                location: origin.location(),
                what: "big-endian bit-field position".to_string(),
            })?
    } else {
        start_bit
    };
    Ok(BitfieldSlice {
        offset,
        storage_bytes,
        bit_position,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BaseKey {
    name: BaseName,
    size: u64,
    signed: bool,
    kind: BaseKind,
}

/// The normalized type graph a frontend produces.
#[derive(Debug)]
pub struct TypeGraph {
    target: Target,
    nodes: Vec<Node>,
    base_intern: BTreeMap<BaseKey, TypeId>,
    qualified_intern: BTreeMap<(TypeId, Qualifier), TypeId>,
    void: Option<TypeId>,
    pointer: Option<TypeId>,
}

impl TypeGraph {
    /// A graph for one target ABI.
    pub fn new(target: Target) -> Self {
        TypeGraph {
            target,
            nodes: Vec::new(),
            base_intern: BTreeMap::new(),
            qualified_intern: BTreeMap::new(),
            void: None,
            pointer: None,
        }
    }

    /// Target ABI this graph is normalized for.
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Append a node verbatim.
    pub fn push(&mut self, node: Node) -> TypeId {
        let id = TypeId::try_from(self.nodes.len()).expect("node count fits in u32");
        self.nodes.push(node);
        id
    }

    /// Node by id.
    pub fn node(&self, id: TypeId) -> &Node {
        &self.nodes[id as usize]
    }

    /// Register an empty aggregate placeholder that is filled in later.
    ///
    /// Frontends call this before resolving members so that recursive records can
    /// refer back to the aggregate being built.
    pub fn composite_slot(&mut self) -> TypeId {
        let id = TypeId::try_from(self.nodes.len()).expect("node count fits in u32");
        self.push(Node::Composite(CompositeRecord {
            name: None,
            kind: CompositeKind::Struct,
            size: None,
            alignment: None,
            members: Vec::new(),
            domain: None,
            origin: Origin::Synthetic {
                tag: format!("slot_{id}"),
            },
            incomplete: false,
            unsupported: None,
        }))
    }

    /// Register an alias whose target is not known yet.
    ///
    /// `typedef struct Node Node;` makes the alias refer to records that refer back
    /// to the alias, so the alias has to exist before its target resolves.
    pub fn typedef_slot(&mut self, name: String, origin: Origin) -> TypeId {
        self.push(Node::Typedef(TypedefRecord {
            name,
            target: TypeId::MAX,
            domain: None,
            origin,
        }))
    }

    /// Attach the name domain a record was defined in.
    pub fn set_domain(&mut self, id: TypeId, domain: Option<String>) -> Result<()> {
        match self.nodes.get_mut(id as usize) {
            Some(Node::Composite(record)) => record.domain = domain,
            Some(Node::Enum(record)) => record.domain = domain,
            Some(Node::Typedef(record)) => record.domain = domain,
            Some(_) => {}
            None => {
                return Err(Error::Message(format!("type id {id} does not exist")));
            }
        }
        Ok(())
    }

    /// Fill in the target of an alias created by [`TypeGraph::typedef_slot`].
    pub fn set_typedef_target(&mut self, id: TypeId, target: TypeId) -> Result<()> {
        match self.nodes.get_mut(id as usize) {
            Some(Node::Typedef(record)) => {
                record.target = target;
                Ok(())
            }
            _ => Err(Error::Message(format!(
                "type id {id} is not a typedef record"
            ))),
        }
    }

    /// Mutate an aggregate registered earlier.
    ///
    /// Frontends register every aggregate before resolving its members, so that
    /// self-referential records (`struct Node { struct Node *next; }`) resolve to
    /// a stable id instead of recursing.
    pub fn composite_mut(&mut self, id: TypeId) -> Result<&mut CompositeRecord> {
        match self.nodes.get_mut(id as usize) {
            Some(Node::Composite(record)) => Ok(record),
            _ => Err(Error::Message(format!(
                "type id {id} is not an aggregate record"
            ))),
        }
    }

    /// All node ids in creation order.
    pub fn ids(&self) -> impl Iterator<Item = TypeId> + '_ {
        0..TypeId::try_from(self.nodes.len()).expect("node count fits in u32")
    }

    /// Interned base unit.
    pub fn base(&mut self, record: BaseRecord) -> TypeId {
        let key = BaseKey {
            name: record.name.clone(),
            size: record.size,
            signed: record.signed,
            kind: record.kind,
        };
        if let Some(id) = self.base_intern.get(&key) {
            return *id;
        }
        let name = record.name.clone();
        let id = self.push(Node::Base(record));
        self.base_intern.insert(key, id);
        match name {
            BaseName::Void => self.void = Some(id),
            BaseName::Pointer => self.pointer = Some(id),
            _ => {}
        }
        id
    }

    /// The synthetic `void` unit.
    pub fn void(&mut self) -> TypeId {
        if let Some(id) = self.void {
            return id;
        }
        self.base(BaseRecord {
            name: BaseName::Void,
            size: 0,
            signed: false,
            kind: BaseKind::Void,
            alignment: None,
            unsupported_reason: None,
            origin: Origin::Synthetic {
                tag: "void".to_string(),
            },
        })
    }

    /// The synthetic pointer-sized unit.
    pub fn pointer_base(&mut self) -> TypeId {
        if let Some(id) = self.pointer {
            return id;
        }
        let size = self.target.pointer_size;
        self.base(BaseRecord {
            name: BaseName::Pointer,
            size,
            signed: false,
            kind: BaseKind::Pointer,
            alignment: None,
            unsupported_reason: None,
            origin: Origin::Synthetic {
                tag: "pointer".to_string(),
            },
        })
    }

    /// Interned bit-field storage unit.
    pub fn bit_storage(&mut self, signed: bool, bytes: u8) -> TypeId {
        self.base(BaseRecord {
            name: BaseName::BitStorage { signed, bytes },
            size: u64::from(bytes),
            signed,
            kind: BaseKind::Int,
            alignment: None,
            unsupported_reason: None,
            origin: Origin::Synthetic {
                tag: format!("bit_storage_{bytes}"),
            },
        })
    }

    /// Interned qualifier wrapper.
    pub fn qualified(&mut self, target: TypeId, qualifier: Qualifier) -> TypeId {
        if let Some(id) = self.qualified_intern.get(&(target, qualifier)) {
            return *id;
        }
        let id = self.push(Node::Qualified(QualifiedRecord { target, qualifier }));
        self.qualified_intern.insert((target, qualifier), id);
        id
    }

    /// Pointer to `target`.
    pub fn pointer_to(&mut self, target: TypeId, size: Option<u64>) -> TypeId {
        self.push(Node::Pointer(PointerRecord {
            target,
            size,
            reference_kind: None,
        }))
    }

    /// C++ reference lowered to a pointer.
    pub fn reference_to(&mut self, target: TypeId, kind: ReferenceKind) -> TypeId {
        self.push(Node::Pointer(PointerRecord {
            target,
            size: None,
            reference_kind: Some(kind),
        }))
    }

    /// Fixed-length array.
    pub fn array_of(&mut self, element: TypeId, count: u64) -> TypeId {
        self.push(Node::Array(ArrayRecord { element, count }))
    }

    /// Function signature.
    pub fn function(
        &mut self,
        return_type: TypeId,
        parameters: Vec<(Option<String>, TypeId)>,
        variadic: bool,
        calling_convention: Option<String>,
    ) -> TypeId {
        self.push(Node::Function(FunctionRecord {
            return_type,
            parameters,
            variadic,
            calling_convention,
        }))
    }

    /// Normalize one bit-field member.
    ///
    /// `byte_bit_start` is the address-order bit offset from the start of the
    /// containing aggregate; `declared_signed` is the signedness of the declared
    /// bit-field type and selects the storage unit's signedness.
    pub fn bitfield_member(
        &mut self,
        name: Option<String>,
        origin: &Origin,
        byte_bit_start: u64,
        bit_length: u64,
        declared: TypeId,
        declared_signed: bool,
    ) -> Result<Member> {
        let slice = bitfield_slice(origin, byte_bit_start, bit_length, self.target.endian)?;
        let storage = self.bit_storage(declared_signed, slice.storage_bytes);
        Ok(Member {
            name: name.clone(),
            offset: slice.offset,
            ty: declared,
            bitfield: Some(BitfieldInfo {
                bit_length,
                bit_position: slice.bit_position,
                storage,
            }),
            anonymous: name.is_none(),
        })
    }

    /// Follow typedef and qualifier wrappers to the underlying node.
    pub fn strip_wrappers(&self, mut id: TypeId) -> TypeId {
        let mut guard = 0usize;
        loop {
            guard += 1;
            if guard > self.nodes.len() + 1 {
                return id;
            }
            match &self.nodes[id as usize] {
                Node::Typedef(record) => id = record.target,
                Node::Qualified(record) => id = record.target,
                _ => return id,
            }
        }
    }

    /// True when the node resolves to a signed integer base unit.
    pub fn base_signed(&self, id: TypeId) -> Option<bool> {
        match &self.nodes[self.strip_wrappers(id) as usize] {
            Node::Base(record) => Some(record.signed),
            _ => None,
        }
    }

    /// Build the output document.
    ///
    /// Names are assigned here, never by the frontends, so that DWARF and PDB
    /// input follow exactly one naming rule.
    pub fn emit(
        mut self,
        image_base: Option<u64>,
        symbols: BTreeMap<String, GlobalSymbol>,
        functions: BTreeMap<String, GlobalFunction>,
    ) -> Result<IsfDocument> {
        self.void();
        self.pointer_base();
        let naming = self.assign_names()?;
        let target = self.target.clone();
        let endian = target.endian;
        let mut document = IsfDocument::empty(target, image_base);
        let mut used = naming.used.clone();

        for id in self.ids() {
            match self.node(id) {
                Node::Base(record) => {
                    if let Some(name) = naming.name_of.get(&id) {
                        document
                            .base_types
                            .insert(name.clone(), base_entry(record, endian));
                    }
                }
                Node::Composite(record) => {
                    let kind = naming.kind_of[&id];
                    if kind == EmitKind::Opaque {
                        let size = record.size.ok_or_else(|| Error::UnsupportedLayout {
                            location: record.origin.location(),
                            detail:
                                "aggregate cannot be represented statically and has no byte_size, so it cannot be emitted even as opaque"
                                    .to_string(),
                        })?;
                        let name = naming.name_of[&id].clone();
                        document.base_types.insert(
                            name,
                            BaseType {
                                kind: BaseKind::Opaque,
                                size,
                                signed: false,
                                endian,
                                alignment: record.alignment,
                                unsupported_reason: Some(
                                    record
                                        .unsupported
                                        .clone()
                                        .unwrap_or_else(|| "unsupported aggregate".to_string()),
                                ),
                            },
                        );
                        continue;
                    }
                    let size = match (record.size, record.incomplete) {
                        (Some(size), _) => size,
                        (None, true) => 0,
                        (None, false) => {
                            return Err(Error::UnsupportedLayout {
                                location: record.origin.location(),
                                detail: "aggregate definition has no byte_size".to_string(),
                            });
                        }
                    };
                    let name = naming.name_of[&id].clone();
                    let fields = self.user_fields(&naming, record)?;
                    document.user_types.insert(
                        name,
                        UserType {
                            kind: record.kind,
                            size,
                            fields,
                            alignment: record.alignment,
                            incomplete: if record.incomplete { Some(true) } else { None },
                            unsupported_reason: if record.incomplete {
                                record.unsupported.clone()
                            } else {
                                None
                            },
                        },
                    );
                }
                Node::Enum(record) => {
                    let kind = naming.kind_of[&id];
                    let name = naming.name_of[&id].clone();
                    if kind == EmitKind::Opaque {
                        document.base_types.insert(
                            name,
                            BaseType {
                                kind: BaseKind::Opaque,
                                size: record.size,
                                signed: false,
                                endian,
                                alignment: None,
                                unsupported_reason: Some(
                                    record
                                        .unsupported
                                        .clone()
                                        .unwrap_or_else(|| "unsupported enumeration".to_string()),
                                ),
                            },
                        );
                        continue;
                    }
                    let mut constants = BTreeMap::new();
                    let mut taken = BTreeSet::new();
                    for (constant, value) in &record.constants {
                        let constant = unique_name(&mut taken, constant);
                        constants.insert(constant, *value);
                    }
                    let signed_hint = record.constants.iter().any(|(_, v)| v.is_negative());
                    let base = match record.base {
                        Some(base) => self.enum_base_name(base, record.size, signed_hint, &naming),
                        None => None,
                    };
                    let base = match base {
                        Some(name) => name,
                        None => ensure_int_base(
                            &mut document.base_types,
                            &mut used,
                            record.size,
                            signed_hint,
                            endian,
                        ),
                    };
                    document.enums.insert(
                        name,
                        EnumType {
                            size: record.size,
                            base: Some(base),
                            constants,
                        },
                    );
                }
                Node::Typedef(record) => {
                    let name = naming.name_of[&id].clone();
                    let target = self.ref_of(&naming, record.target)?;
                    document.typedefs.insert(name, target);
                }
                _ => {}
            }
        }

        for (name, symbol) in symbols {
            let ty = match symbol.ty {
                Some(id) => Some(self.ref_of(&naming, id)?),
                None => None,
            };
            document.symbols.insert(
                name,
                Symbol {
                    address: symbol.address,
                    ty,
                },
            );
        }
        for (name, function) in functions {
            let signature = function.signature;
            let return_type = self.ref_of(&naming, signature.return_type)?;
            let mut parameters = Vec::with_capacity(signature.parameters.len());
            for (parameter_name, id) in signature.parameters {
                parameters.push(Parameter {
                    name: parameter_name,
                    ty: self.ref_of(&naming, id)?,
                });
            }
            document.functions.insert(
                name,
                IsfFunction {
                    address: function.address,
                    return_type,
                    parameters,
                    variadic: if signature.variadic { Some(true) } else { None },
                    calling_convention: signature.calling_convention,
                },
            );
        }

        Ok(document)
    }

    /// Name of the underlying integer unit of an enum, when the source states one
    /// that already matches the enum size.
    fn enum_base_name(
        &self,
        base: TypeId,
        size: u64,
        _signed_hint: bool,
        naming: &Naming,
    ) -> Option<String> {
        let stripped = self.strip_wrappers(base);
        match self.node(stripped) {
            Node::Base(record)
                if record.size == size
                    && !matches!(
                        record.kind,
                        BaseKind::Void | BaseKind::Pointer | BaseKind::Opaque
                    ) =>
            {
                naming.name_of.get(&stripped).cloned()
            }
            _ => None,
        }
    }

    fn user_fields(
        &self,
        naming: &Naming,
        record: &CompositeRecord,
    ) -> Result<BTreeMap<String, Field>> {
        let mut fields = BTreeMap::new();
        let mut taken = BTreeSet::new();
        let mut anonymous_index = 0usize;
        for member in &record.members {
            let raw = match &member.name {
                Some(name) if !name.is_empty() => name.clone(),
                _ => {
                    let name = format!("unnamed_field_{anonymous_index}");
                    anonymous_index += 1;
                    name
                }
            };
            let name = unique_name(&mut taken, &raw);
            let ty = match member.bitfield {
                Some(bitfield) => TypeRef::Bitfield {
                    bit_length: bitfield.bit_length,
                    bit_position: bitfield.bit_position,
                    ty: Box::new(self.ref_of(naming, bitfield.storage)?),
                    declared_type: Some(Box::new(self.ref_of(naming, member.ty)?)),
                },
                None => self.ref_of(naming, member.ty)?,
            };
            fields.insert(
                name,
                Field {
                    offset: member.offset,
                    ty,
                    anonymous: if member.anonymous { Some(true) } else { None },
                },
            );
        }
        Ok(fields)
    }

    /// Lower a node to a wire reference.
    fn ref_of(&self, naming: &Naming, id: TypeId) -> Result<TypeRef> {
        let mut qualifiers = Vec::new();
        let mut current = id;
        let mut guard = 0usize;
        while let Node::Qualified(record) = self.node(current) {
            qualifiers.push(record.qualifier);
            current = record.target;
            guard += 1;
            if guard > self.nodes.len() {
                return Err(Error::InvalidDocument(format!(
                    "qualifier cycle at type id {id}"
                )));
            }
        }
        let reference = match self.node(current) {
            Node::Base(record) => named_ref(
                match record.kind {
                    BaseKind::Void => EmitKind::Base,
                    BaseKind::Pointer => EmitKind::Base,
                    _ if record.unsupported_reason.is_some() => EmitKind::Opaque,
                    _ => EmitKind::Base,
                },
                self.name_of(naming, current)?,
                qualifiers,
            ),
            Node::Composite(record) => {
                let kind = naming.kind_of[&current];
                match kind {
                    EmitKind::Opaque => {
                        named_ref(EmitKind::Opaque, self.name_of(naming, current)?, qualifiers)
                    }
                    EmitKind::Struct | EmitKind::Union => {
                        named_ref(kind, self.name_of(naming, current)?, qualifiers)
                    }
                    _ => {
                        return Err(Error::InvalidDocument(format!(
                            "aggregate {} has an invalid emitted kind",
                            record.origin.location()
                        )));
                    }
                }
            }
            Node::Enum(_) => {
                let kind = naming.kind_of[&current];
                match kind {
                    EmitKind::Opaque => {
                        named_ref(EmitKind::Opaque, self.name_of(naming, current)?, qualifiers)
                    }
                    _ => named_ref(EmitKind::Enum, self.name_of(naming, current)?, qualifiers),
                }
            }
            Node::Typedef(_) => named_ref(
                EmitKind::Typedef,
                self.name_of(naming, current)?,
                qualifiers,
            ),
            Node::Pointer(record) => TypeRef::Pointer {
                subtype: Box::new(self.ref_of(naming, record.target)?),
                size: record
                    .size
                    .filter(|size| *size != self.target.pointer_size && *size > 0),
                qualifiers,
                reference_kind: record.reference_kind,
            },
            Node::Array(record) => TypeRef::Array {
                count: record.count,
                subtype: Box::new(self.ref_of(naming, record.element)?),
                qualifiers,
            },
            Node::Function(record) => {
                let mut parameters = Vec::with_capacity(record.parameters.len());
                for (name, id) in &record.parameters {
                    parameters.push(Parameter {
                        name: name.clone(),
                        ty: self.ref_of(naming, *id)?,
                    });
                }
                TypeRef::Function {
                    return_type: Box::new(self.ref_of(naming, record.return_type)?),
                    parameters,
                    variadic: if record.variadic { Some(true) } else { None },
                    calling_convention: record.calling_convention.clone(),
                    qualifiers,
                }
            }
            Node::Qualified(_) => unreachable!("qualifier wrappers are peeled above"),
        };
        Ok(reference)
    }

    fn name_of(&self, naming: &Naming, id: TypeId) -> Result<String> {
        naming.name_of.get(&id).cloned().ok_or_else(|| {
            Error::InvalidDocument(format!(
                "{} was not assigned an output name",
                self.origin_of(id).location()
            ))
        })
    }

    /// Name domain a record was defined in, used to tell same-named types apart.
    fn domain_of(&self, id: TypeId) -> Option<&str> {
        match self.node(id) {
            Node::Composite(record) => record.domain.as_deref(),
            Node::Enum(record) => record.domain.as_deref(),
            Node::Typedef(record) => record.domain.as_deref(),
            _ => None,
        }
    }

    fn origin_of(&self, id: TypeId) -> Origin {
        match self.node(id) {
            Node::Base(record) => record.origin.clone(),
            Node::Composite(record) => record.origin.clone(),
            Node::Enum(record) => record.origin.clone(),
            Node::Typedef(record) => record.origin.clone(),
            _ => Origin::Synthetic {
                tag: format!("type_{id}"),
            },
        }
    }

    fn assign_names(&self) -> Result<Naming> {
        let mut kind_of: BTreeMap<TypeId, EmitKind> = BTreeMap::new();
        let mut named: BTreeMap<String, Vec<TypeId>> = BTreeMap::new();
        let mut anonymous: Vec<TypeId> = Vec::new();
        let mut bit_storage: Vec<TypeId> = Vec::new();
        for id in self.ids() {
            match self.node(id) {
                Node::Base(record) => {
                    let kind = if record.unsupported_reason.is_some() {
                        EmitKind::Opaque
                    } else {
                        EmitKind::Base
                    };
                    kind_of.insert(id, kind);
                    match &record.name {
                        BaseName::Void => {
                            named.entry("void".to_string()).or_default().push(id);
                        }
                        BaseName::Pointer => {
                            named.entry("pointer".to_string()).or_default().push(id);
                        }
                        BaseName::Source(name) if !name.is_empty() => {
                            named.entry(name.clone()).or_default().push(id);
                        }
                        BaseName::Source(_) => anonymous.push(id),
                        BaseName::BitStorage { .. } => bit_storage.push(id),
                    }
                }
                Node::Composite(record) => {
                    // A declaration that could not be linked stays a (declared)
                    // aggregate and explains itself; only a definition we cannot
                    // represent becomes an opaque unit.
                    let kind = if record.unsupported.is_some() && !record.incomplete {
                        EmitKind::Opaque
                    } else {
                        match record.kind {
                            CompositeKind::Struct => EmitKind::Struct,
                            CompositeKind::Union => EmitKind::Union,
                        }
                    };
                    kind_of.insert(id, kind);
                    match &record.name {
                        Some(name) if !name.is_empty() => {
                            named.entry(name.clone()).or_default().push(id);
                        }
                        _ => anonymous.push(id),
                    }
                }
                Node::Enum(record) => {
                    let kind = if record.unsupported.is_some() {
                        EmitKind::Opaque
                    } else {
                        EmitKind::Enum
                    };
                    kind_of.insert(id, kind);
                    match &record.name {
                        Some(name) if !name.is_empty() => {
                            named.entry(name.clone()).or_default().push(id);
                        }
                        _ => anonymous.push(id),
                    }
                }
                Node::Typedef(record) => {
                    kind_of.insert(id, EmitKind::Typedef);
                    named.entry(record.name.clone()).or_default().push(id);
                }
                Node::Pointer(_) | Node::Array(_) | Node::Qualified(_) | Node::Function(_) => {}
            }
        }

        let mut name_of: BTreeMap<TypeId, String> = BTreeMap::new();
        let mut used: BTreeSet<String> = BTreeSet::new();

        // The synthetic `void` and pointer units own their names; a source type
        // that happens to be called the same way is suffixed instead.
        for (reserved, synthetic) in [("void", BaseName::Void), ("pointer", BaseName::Pointer)] {
            let ids = named.remove(reserved).unwrap_or_default();
            let mut keep = Vec::new();
            let mut holder = None;
            for id in ids {
                let is_synthetic =
                    matches!(self.node(id), Node::Base(record) if record.name == synthetic);
                if is_synthetic && holder.is_none() {
                    holder = Some(id);
                } else {
                    keep.push(id);
                }
            }
            if let Some(id) = holder {
                name_of.insert(id, reserved.to_string());
                used.insert(reserved.to_string());
            }
            if !keep.is_empty() {
                named.insert(reserved.to_string(), keep);
            }
        }

        for (name, ids) in named {
            self.assign_group(&name, &ids, &mut used, &mut name_of);
        }
        for id in anonymous {
            let candidate = format!("__anon_{}", self.origin_of(id).token());
            let name = unique_name(&mut used, &candidate);
            name_of.insert(id, name);
        }
        for id in bit_storage {
            let (signed, bytes) = match self.node(id) {
                Node::Base(BaseRecord {
                    name: BaseName::BitStorage { signed, bytes },
                    ..
                }) => (*signed, *bytes),
                _ => unreachable!("bit storage list holds bit storage bases"),
            };
            let base = format!(
                "__isf_bits_{}{}",
                if signed { 'i' } else { 'u' },
                u64::from(bytes) * 8
            );
            let name = unique_name_with(&mut used, &base, "__storage");
            name_of.insert(id, name);
        }

        Ok(Naming {
            name_of,
            kind_of,
            used,
        })
    }

    fn assign_group(
        &self,
        name: &str,
        ids: &[TypeId],
        used: &mut BTreeSet<String>,
        name_of: &mut BTreeMap<TypeId, String>,
    ) {
        let mut classes: Vec<Vec<TypeId>> = Vec::new();
        for &id in ids {
            match classes
                .iter_mut()
                .find(|class| self.equivalent(class[0], id))
            {
                Some(class) => class.push(id),
                None => classes.push(vec![id]),
            }
        }
        let mut first = true;
        for class in classes {
            let candidate = if first && !used.contains(name) {
                name.to_string()
            } else {
                match self.domain_of(class[0]) {
                    // The compilation unit is the real name domain of a type, so it
                    // names the variant; the record token stays as a fallback.
                    Some(domain) if !domain.is_empty() => format!("{name}@{domain}"),
                    _ => format!("{name}__{}", self.origin_of(class[0]).token()),
                }
            };
            let assigned = unique_name(used, &candidate);
            for id in class {
                name_of.insert(id, assigned.clone());
            }
            first = false;
        }
    }

    /// Structural equivalence of two nodes, tolerant of recursion.
    ///
    /// Two definitions that describe the same layout are the same type even when a
    /// container stores them under different source records, which is what lets the
    /// frontends merge duplicate definitions instead of guessing between them.
    pub fn equivalent(&self, a: TypeId, b: TypeId) -> bool {
        let mut memo = BTreeSet::new();
        self.equivalent_inner(a, b, &mut memo)
    }

    fn equivalent_inner(
        &self,
        a: TypeId,
        b: TypeId,
        memo: &mut BTreeSet<(TypeId, TypeId)>,
    ) -> bool {
        if a == b {
            return true;
        }
        let key = if a < b { (a, b) } else { (b, a) };
        if !memo.insert(key) {
            return true;
        }
        match (self.node(a), self.node(b)) {
            (Node::Base(x), Node::Base(y)) => {
                x.name == y.name
                    && x.size == y.size
                    && x.signed == y.signed
                    && x.kind == y.kind
                    && x.unsupported_reason.is_some() == y.unsupported_reason.is_some()
            }
            (Node::Pointer(x), Node::Pointer(y)) => {
                x.size == y.size
                    && x.reference_kind == y.reference_kind
                    && self.equivalent_inner(x.target, y.target, memo)
            }
            (Node::Array(x), Node::Array(y)) => {
                x.count == y.count && self.equivalent_inner(x.element, y.element, memo)
            }
            (Node::Qualified(x), Node::Qualified(y)) => {
                x.qualifier == y.qualifier && self.equivalent_inner(x.target, y.target, memo)
            }
            (Node::Composite(x), Node::Composite(y)) => {
                x.kind == y.kind
                    && x.size == y.size
                    && x.alignment == y.alignment
                    && x.incomplete == y.incomplete
                    && x.unsupported.is_some() == y.unsupported.is_some()
                    && x.members.len() == y.members.len()
                    && x.members
                        .iter()
                        .zip(y.members.iter())
                        .all(|(m, n)| self.member_equivalent(m, n, memo))
            }
            (Node::Enum(x), Node::Enum(y)) => {
                x.size == y.size
                    && x.constants == y.constants
                    && x.unsupported.is_some() == y.unsupported.is_some()
                    && match (x.base, y.base) {
                        (None, None) => true,
                        (Some(a), Some(b)) => self.equivalent_inner(a, b, memo),
                        _ => false,
                    }
            }
            (Node::Typedef(x), Node::Typedef(y)) => self.equivalent_inner(x.target, y.target, memo),
            (Node::Function(x), Node::Function(y)) => {
                x.variadic == y.variadic
                    && x.calling_convention == y.calling_convention
                    && self.equivalent_inner(x.return_type, y.return_type, memo)
                    && x.parameters.len() == y.parameters.len()
                    && x.parameters
                        .iter()
                        .zip(y.parameters.iter())
                        .all(|(p, q)| p.0 == q.0 && self.equivalent_inner(p.1, q.1, memo))
            }
            _ => false,
        }
    }

    fn member_equivalent(
        &self,
        a: &Member,
        b: &Member,
        memo: &mut BTreeSet<(TypeId, TypeId)>,
    ) -> bool {
        if a.name != b.name || a.offset != b.offset || a.anonymous != b.anonymous {
            return false;
        }
        match (a.bitfield, b.bitfield) {
            (None, None) => {}
            (Some(x), Some(y)) => {
                if x.bit_length != y.bit_length
                    || x.bit_position != y.bit_position
                    || !self.equivalent_inner(x.storage, y.storage, memo)
                {
                    return false;
                }
            }
            _ => return false,
        }
        self.equivalent_inner(a.ty, b.ty, memo)
    }
}

/// An object to publish in the `symbols` table.
#[derive(Clone, Debug)]
pub struct GlobalSymbol {
    /// Static address when the debug information gives one.
    pub address: Option<u64>,
    /// Object type when known.
    pub ty: Option<TypeId>,
}

/// A function to publish in the `functions` table.
#[derive(Clone, Debug)]
pub struct GlobalFunction {
    /// Static address when the debug information gives one.
    pub address: Option<u64>,
    /// Signature.
    pub signature: FunctionRecord,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EmitKind {
    Base,
    Struct,
    Union,
    Enum,
    Typedef,
    Opaque,
}

struct Naming {
    name_of: BTreeMap<TypeId, String>,
    kind_of: BTreeMap<TypeId, EmitKind>,
    used: BTreeSet<String>,
}

fn named_ref(kind: EmitKind, name: String, qualifiers: Vec<Qualifier>) -> TypeRef {
    match kind {
        EmitKind::Base | EmitKind::Opaque => TypeRef::Base { name, qualifiers },
        EmitKind::Struct => TypeRef::Struct { name, qualifiers },
        EmitKind::Union => TypeRef::Union { name, qualifiers },
        EmitKind::Enum => TypeRef::Enum { name, qualifiers },
        EmitKind::Typedef => TypeRef::Typedef { name, qualifiers },
    }
}

fn base_entry(record: &BaseRecord, endian: crate::isf::Endian) -> BaseType {
    BaseType {
        kind: record.kind,
        size: record.size,
        signed: record.signed,
        endian,
        alignment: record.alignment,
        unsupported_reason: record.unsupported_reason.clone(),
    }
}

/// Insert `base` into `used`, appending `__{n}` when it is taken.
fn unique_name(used: &mut BTreeSet<String>, base: &str) -> String {
    if used.insert(base.to_string()) {
        return base.to_string();
    }
    let mut n = 2u32;
    loop {
        let candidate = format!("{base}__{n}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        n += 1;
    }
}

/// Insert `base` into `used`, appending `suffix` while it is taken.
fn unique_name_with(used: &mut BTreeSet<String>, base: &str, suffix: &str) -> String {
    let mut candidate = base.to_string();
    while used.contains(&candidate) {
        candidate.push_str(suffix);
    }
    used.insert(candidate.clone());
    candidate
}

/// Ensure an integer base unit of the requested width exists and return its name.
fn ensure_int_base(
    base_types: &mut BTreeMap<String, BaseType>,
    used: &mut BTreeSet<String>,
    size: u64,
    signed: bool,
    endian: crate::isf::Endian,
) -> String {
    let bits = size.saturating_mul(8);
    let requested = format!("{}{bits}_t", if signed { "int" } else { "uint" });
    if let Some(existing) = base_types.get(&requested) {
        if existing.size == size
            && existing.signed == signed
            && matches!(
                existing.kind,
                BaseKind::Int | BaseKind::Char | BaseKind::Bool
            )
            && existing.unsupported_reason.is_none()
        {
            return requested;
        }
    }
    let name = unique_name_with(used, &requested, "__enum");
    base_types.insert(
        name.clone(),
        BaseType {
            kind: BaseKind::Int,
            size,
            signed,
            endian,
            alignment: None,
            unsupported_reason: None,
        },
    );
    name
}
