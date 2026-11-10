//! Native PDB frontend: CodeView type and symbol records into the normalized type
//! graph.
//!
//! The frontend reads the TPI stream in a first pass, keeping every record under
//! its `TypeIndex`, and resolves types in a second pass. Forward references are
//! linked to their complete definition by unique name first and by name second; a
//! name with several incompatible definitions is reported instead of silently
//! picking one. Symbols come from both the global symbol stream and every module
//! symbol stream, and addresses are formed from the PDB section map (including
//! OMAP when present) plus the image base.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, Read, Seek};
use std::path::{Path, PathBuf};

use object::Object;
use pdb::{
    AddressMap, FallibleIterator, Indirection, MachineType, PDB, PdbInternalSectionOffset,
    PointerMode, PrimitiveKind, PrimitiveType, TypeData, TypeIndex, Variant,
};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::isf::{
    BaseKind, CompositeKind, Endian, IntValue, IsfDocument, Qualifier, ReferenceKind, Target,
};
use crate::normalize::{
    BaseName, BaseRecord, EnumRecord, FunctionRecord, GlobalFunction, GlobalSymbol, Member, Node,
    Origin, TypeGraph, TypeId,
};

/// Decode a CodeView raw string without needing the PDB string table.
trait RawStringExt {
    fn raw(&self) -> String;
}

impl RawStringExt for pdb::RawString<'_> {
    fn raw(&self) -> String {
        self.to_string().into_owned()
    }
}

/// Convert one PDB input.
pub(crate) fn convert(
    pdb_path: &Path,
    image: Option<&Path>,
    image_base: Option<u64>,
    detail: crate::Detail,
) -> Result<IsfDocument> {
    let file = std::fs::File::open(pdb_path).map_err(|e| Error::io(pdb_path, e))?;
    let mut pdb = PDB::open(BufReader::new(file)).map_err(|e| pdb_error(pdb_path, e))?;

    let machine = {
        let information = pdb
            .debug_information()
            .map_err(|e| pdb_error(pdb_path, e))?;
        information
            .machine_type()
            .map_err(|e| pdb_error(pdb_path, e))?
    };
    let (architecture, pointer_size, endian) = target_for_machine(machine)?;
    let information = pdb.pdb_information().map_err(|e| pdb_error(pdb_path, e))?;
    let pdb_guid = information.guid;
    let pdb_age = information.age;

    let mut base = image_base;
    if let Some(image_path) = image {
        let bytes = std::fs::read(image_path).map_err(|e| Error::io(image_path, e))?;
        let parsed = object::File::parse(&bytes[..]).map_err(|e| Error::Corrupt {
            path: image_path.into(),
            detail: e.to_string(),
        })?;
        if parsed.format() != object::BinaryFormat::Pe {
            return Err(Error::UnsupportedContainer {
                path: image_path.into(),
                detail: "the image paired with a PDB must be a PE executable".to_string(),
            });
        }
        if image_base.is_none() {
            base = Some(parsed.relative_address_base());
        }
        if let Some(codeview) = parsed.pdb_info().map_err(|e| Error::Corrupt {
            path: image_path.into(),
            detail: e.to_string(),
        })? {
            let guid = uuid_from_codeview(codeview.guid());
            if guid != pdb_guid {
                return Err(Error::DebugFileMismatch {
                    image: image_path.into(),
                    debug_file: pdb_path.into(),
                    detail: format!("CodeView GUID {guid} does not match the PDB GUID {pdb_guid}"),
                });
            }
            if codeview.age() > pdb_age {
                return Err(Error::DebugFileMismatch {
                    image: image_path.into(),
                    debug_file: pdb_path.into(),
                    detail: format!(
                        "CodeView age {} is newer than the PDB age {pdb_age}",
                        codeview.age()
                    ),
                });
            }
        }
    }
    if detail.needs_addresses() && base.is_none() {
        return Err(Error::MissingImageBase);
    }

    let type_info = pdb.type_information().map_err(|e| pdb_error(pdb_path, e))?;
    let mut finder = type_info.finder();
    let mut types: BTreeMap<u32, TypeData<'_>> = BTreeMap::new();
    let mut unparsed: BTreeMap<u32, String> = BTreeMap::new();
    {
        let mut iter = type_info.iter();
        while let Some(item) = iter.next().map_err(|e| pdb_error(pdb_path, e))? {
            finder.update(&iter);
            let index = item.index().0;
            match item.parse() {
                Ok(data) => {
                    types.insert(index, data);
                }
                Err(error) => {
                    unparsed.insert(index, error.to_string());
                }
            }
        }
    }
    if types.is_empty() {
        return Err(Error::NoDebugInfo {
            path: pdb_path.into(),
        });
    }

    let mut resolver = Resolver {
        path: pdb_path.into(),
        graph: TypeGraph::new(Target {
            architecture,
            pointer_size,
            endian,
        }),
        cache: BTreeMap::new(),
        types,
        unparsed,
        finder,
        definitions: BTreeMap::new(),
        parents: BTreeMap::new(),
        modules_of: BTreeMap::new(),
        module_domains: BTreeMap::new(),
        symbols: BTreeMap::new(),
        functions: BTreeMap::new(),
        pointer_size,
    };
    // The module/type association gives type records their name domain, so it has
    // to be known before any forward reference is linked.
    let pending = collect_pending(pdb_path, &mut pdb)?;
    resolver.prepare_indexes();
    resolver.prepare_domains(&pending.modules);
    resolver.resolve_all()?;
    // Aliases (`S_UDT`) are type information, so they are always collected; only
    // addresses need a linked image and an image base.
    let address_map = if detail.needs_addresses() {
        Some(pdb.address_map().map_err(|e| pdb_error(pdb_path, e))?)
    } else {
        None
    };
    let addresses = match (&address_map, base) {
        (Some(map), Some(base)) => Some((map, base)),
        (Some(_), None) => return Err(Error::MissingImageBase),
        _ => None,
    };
    apply_pending(&mut resolver, pending, addresses, detail)?;
    let Resolver {
        graph,
        symbols,
        functions,
        ..
    } = resolver;
    let image_base = if detail.needs_addresses() { base } else { None };
    let document = graph.emit(image_base, symbols, functions)?;
    document.validate()?;
    Ok(document)
}

/// Symbol kinds this crate does not decode are skipped; stream damage is not.
fn skippable_symbol(error: &pdb::Error) -> bool {
    matches!(
        error,
        pdb::Error::UnimplementedSymbolKind(_) | pdb::Error::UnimplementedFeature(_)
    )
}

fn pdb_error(path: &Path, error: pdb::Error) -> Error {
    let detail = error.to_string();
    if detail.contains("type not found") || detail.contains("unimplemented") {
        Error::UnsupportedPdbRecord {
            detail: format!("{}: {detail}", path.display()),
        }
    } else {
        Error::Corrupt {
            path: path.into(),
            detail,
        }
    }
}

fn uuid_from_codeview(bytes: [u8; 16]) -> Uuid {
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let node: [u8; 8] = bytes[8..16].try_into().expect("eight bytes");
    Uuid::from_fields(data1, data2, data3, &node)
}

fn target_for_machine(machine: MachineType) -> Result<(String, u64, Endian)> {
    let (name, pointer_size) = match machine {
        MachineType::Amd64 => ("x86_64", 8),
        MachineType::X86 => ("i386", 4),
        MachineType::Arm | MachineType::ArmNT => ("arm", 4),
        MachineType::Arm64 => ("aarch64", 8),
        MachineType::Ia64 => ("ia64", 8),
        other => {
            return Err(Error::UnsupportedTarget {
                machine: format!("{other:?}"),
            });
        }
    };
    Ok((name.to_string(), pointer_size, Endian::Little))
}

fn indirection_size(indirection: Indirection) -> u64 {
    match indirection {
        Indirection::Near16 | Indirection::Far16 | Indirection::Huge16 => 2,
        Indirection::Near32 | Indirection::Far32 => 4,
        Indirection::Near64 => 8,
        Indirection::Near128 => 16,
    }
}

// ---------------------------------------------------------------------------
// Records extracted read-only from the TPI stream
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Spec {
    Base {
        name: String,
        size: u64,
        signed: bool,
        kind: BaseKind,
        reason: Option<String>,
    },
    Pointer {
        target: u32,
        size: u64,
        reference: Option<ReferenceKind>,
        qualifiers: Vec<Qualifier>,
        member_pointer: bool,
    },
    Qualified {
        target: u32,
        qualifiers: Vec<Qualifier>,
    },
    Array {
        element: u32,
        dimensions: Vec<u32>,
        stride: Option<u32>,
    },
    Composite {
        name: String,
        kind: CompositeKind,
        size: u64,
        forward: bool,
        members: Vec<MemberSpec>,
        unsupported: Option<String>,
    },
    Enumeration {
        underlying: u32,
        size: u64,
        signed: bool,
        constants: Vec<(String, IntValue)>,
        forward: bool,
    },
    Procedure {
        return_type: Option<u32>,
        parameters: Vec<u32>,
        calling_convention: String,
    },
    Unsupported(String),
}

/// An aggregate record on its way from the TPI stream into the type graph.
#[derive(Debug)]
struct CompositeParts {
    name: String,
    kind: CompositeKind,
    size: u64,
    forward: bool,
    members: Vec<MemberSpec>,
    unsupported: Option<String>,
}

#[derive(Debug)]
struct MemberSpec {
    name: Option<String>,
    offset: u64,
    kind: MemberKind,
}

#[derive(Debug)]
enum MemberKind {
    Data(u32),
    Bitfield {
        underlying: u32,
        position: u64,
        length: u64,
    },
    BaseClass(u32),
    VirtualFunctionTable,
    Unsupported(String),
}

/// Outcome of linking a forward declaration to its complete definition.
enum Link {
    /// Exactly one candidate definition was found.
    Single(u32),
    /// No candidate definition exists.
    Missing,
    /// Several definitions claim the name with different layouts.
    Ambiguous(String),
}

/// One entry of a flattened field list.
#[derive(Debug)]
enum FieldEntry {
    Member(MemberSpec),
    Enumerate {
        name: String,
        value: Variant,
    },
    VirtualBase(u32),
    /// Entries that describe no object layout (nested types, methods, static
    /// members) never become members.
    LayoutNeutral,
    /// An entry whose layout effect is unknown, which makes the aggregate opaque.
    Other(String),
}

struct Resolver<'t> {
    path: PathBuf,
    graph: TypeGraph,
    cache: BTreeMap<u32, TypeId>,
    types: BTreeMap<u32, TypeData<'t>>,
    unparsed: BTreeMap<u32, String>,
    /// Resolves type indices that are not stored as TPI records (primitives).
    finder: pdb::TypeFinder<'t>,
    /// Complete definitions by (unique name, name).
    definitions: BTreeMap<(Option<String>, String), Vec<u32>>,
    /// Nested type index to containing type index.
    parents: BTreeMap<u32, u32>,
    /// Modules (compilation units) that reach a type record.
    modules_of: BTreeMap<u32, BTreeSet<usize>>,
    /// Path-free label of every module.
    module_domains: BTreeMap<usize, String>,
    symbols: BTreeMap<String, GlobalSymbol>,
    functions: BTreeMap<String, GlobalFunction>,
    pointer_size: u64,
}

impl<'t> Resolver<'t> {
    fn prepare_indexes(&mut self) {
        let mut definitions: BTreeMap<(Option<String>, String), Vec<u32>> = BTreeMap::new();
        for (index, data) in &self.types {
            let (name, unique, forward) = match data {
                TypeData::Class(class) => (
                    class.name.raw(),
                    class.unique_name.map(|name| name.raw()),
                    class.properties.forward_reference(),
                ),
                TypeData::Union(union) => (
                    union.name.raw(),
                    union.unique_name.map(|name| name.raw()),
                    union.properties.forward_reference(),
                ),
                TypeData::Enumeration(enumeration) => (
                    enumeration.name.raw(),
                    enumeration.unique_name.map(|name| name.raw()),
                    enumeration.properties.forward_reference(),
                ),
                _ => continue,
            };
            if !forward && !name.is_empty() {
                definitions.entry((unique, name)).or_default().push(*index);
            }
        }
        let mut parents: BTreeMap<u32, u32> = BTreeMap::new();
        for (parent, data) in &self.types {
            let fields = match data {
                TypeData::Class(class) => class.fields,
                TypeData::Union(union) => Some(union.fields),
                _ => None,
            };
            if let Some(fields) = fields {
                let mut current = Some(fields.0);
                let mut guard = 0usize;
                while let Some(index) = current {
                    guard += 1;
                    if guard > 64 {
                        break;
                    }
                    let Some(TypeData::FieldList(list)) = self.types.get(&index) else {
                        break;
                    };
                    for field in &list.fields {
                        if let TypeData::Nested(nested) = field {
                            parents.entry(nested.nested_type.0).or_insert(*parent);
                        }
                    }
                    current = list.continuation.map(|next| next.0);
                }
            }
        }
        self.definitions = definitions;
        self.parents = parents;
    }

    /// Record which modules reach which type records.
    ///
    /// CodeView type records carry no compilation unit: the only recoverable name
    /// domain is the set of modules whose symbols (transitively) use the record.
    fn prepare_domains(&mut self, modules: &[ModuleTypes]) {
        let mut modules_of: BTreeMap<u32, BTreeSet<usize>> = BTreeMap::new();
        let mut module_domains: BTreeMap<usize, String> = BTreeMap::new();
        for module in modules {
            module_domains.insert(module.index, module.domain.clone());
            let mut seen: BTreeSet<u32> = BTreeSet::new();
            let mut stack: Vec<u32> = module.types.iter().copied().collect();
            let mut edges: Vec<u32> = Vec::new();
            while let Some(current) = stack.pop() {
                if !seen.insert(current) {
                    continue;
                }
                modules_of.entry(current).or_default().insert(module.index);
                edges.clear();
                self.type_edges(current, &mut edges);
                for next in &edges {
                    if !seen.contains(next) {
                        stack.push(*next);
                    }
                }
            }
        }
        self.modules_of = modules_of;
        self.module_domains = module_domains;
    }

    /// Type records a record refers to.
    fn type_edges(&self, index: u32, out: &mut Vec<u32>) {
        match self.types.get(&index) {
            Some(TypeData::Class(class)) => {
                if let Some(fields) = class.fields {
                    self.field_edges(fields, out, 0);
                }
                if let Some(derived) = class.derived_from {
                    out.push(derived.0);
                }
            }
            Some(TypeData::Union(union)) => self.field_edges(union.fields, out, 0),
            Some(TypeData::Enumeration(enumeration)) => {
                out.push(enumeration.underlying_type.0);
                self.field_edges(enumeration.fields, out, 0);
            }
            Some(TypeData::Array(array)) => {
                out.push(array.element_type.0);
                out.push(array.indexing_type.0);
            }
            Some(TypeData::Pointer(pointer)) => out.push(pointer.underlying_type.0),
            Some(TypeData::Modifier(modifier)) => out.push(modifier.underlying_type.0),
            Some(TypeData::Bitfield(bitfield)) => out.push(bitfield.underlying_type.0),
            Some(TypeData::Procedure(procedure)) => {
                if let Some(return_type) = procedure.return_type {
                    out.push(return_type.0);
                }
                out.push(procedure.argument_list.0);
            }
            Some(TypeData::ArgumentList(list)) => {
                out.extend(list.arguments.iter().map(|argument| argument.0));
            }
            _ => {}
        }
    }

    fn field_edges(&self, list: TypeIndex, out: &mut Vec<u32>, depth: usize) {
        if depth > 64 {
            return;
        }
        let Some(TypeData::FieldList(fields)) = self.types.get(&list.0) else {
            return;
        };
        for field in &fields.fields {
            match field {
                TypeData::Member(member) => out.push(member.field_type.0),
                TypeData::BaseClass(base) => out.push(base.base_class.0),
                TypeData::Nested(nested) => out.push(nested.nested_type.0),
                _ => {}
            }
        }
        if let Some(continuation) = fields.continuation {
            self.field_edges(continuation, out, depth + 1);
        }
    }

    /// Path-free label of the single module that uses a record, if it is unique.
    fn record_domain(&self, index: u32) -> Option<String> {
        let modules = self.modules_of.get(&index)?;
        if modules.len() != 1 {
            return None;
        }
        let module = modules.iter().next()?;
        self.module_domains.get(module).cloned()
    }

    /// Narrow candidate definitions to the modules that use the declaration.
    fn scoped_candidates(&self, index: u32, candidates: Vec<u32>) -> Vec<u32> {
        let Some(domains) = self.modules_of.get(&index) else {
            return candidates;
        };
        if domains.is_empty() {
            return candidates;
        }
        let scoped: Vec<u32> = candidates
            .iter()
            .copied()
            .filter(|candidate| {
                self.modules_of
                    .get(candidate)
                    .is_some_and(|modules| !modules.is_disjoint(domains))
            })
            .collect();
        if scoped.is_empty() {
            candidates
        } else {
            scoped
        }
    }

    // -- read-only extraction ---------------------------------------------

    fn primitive(&self, index: u32) -> Result<PrimitiveType> {
        let item = self
            .finder
            .find(TypeIndex(index))
            .map_err(|e| pdb_error(&self.path, e))?;
        match item.parse().map_err(|e| pdb_error(&self.path, e))? {
            TypeData::Primitive(primitive) => Ok(primitive),
            other => Err(Error::UnsupportedPdbRecord {
                detail: format!(
                    "primitive index {index:#x} parsed as a {} record",
                    type_kind(&other)
                ),
            }),
        }
    }

    /// Name recorded for a type record, if it has one.
    fn record_name(&self, index: u32) -> Option<String> {
        match self.types.get(&index)? {
            TypeData::Class(class) => Some(class.name.raw()),
            TypeData::Union(union) => Some(union.name.raw()),
            TypeData::Enumeration(enumeration) => Some(enumeration.name.raw()),
            _ => None,
        }
    }

    fn record(&self, index: u32) -> Result<&TypeData<'t>> {
        if let Some(data) = self.types.get(&index) {
            return Ok(data);
        }
        if let Some(detail) = self.unparsed.get(&index) {
            return Err(Error::UnsupportedPdbRecord {
                detail: format!("type index {index:#x} in {}: {detail}", self.path.display()),
            });
        }
        Err(Error::UnsupportedPdbRecord {
            detail: format!(
                "type index {index:#x} is not present in {}",
                self.path.display()
            ),
        })
    }

    fn qualified_name(&self, index: u32) -> String {
        let mut parts = Vec::new();
        let mut current = Some(index);
        let mut guard = 0usize;
        while let Some(index) = current {
            guard += 1;
            if guard > 64 {
                break;
            }
            let Some(data) = self.types.get(&index) else {
                break;
            };
            match data {
                TypeData::Class(class) => parts.push(class.name.raw()),
                TypeData::Union(union) => parts.push(union.name.raw()),
                TypeData::Enumeration(enumeration) => parts.push(enumeration.name.raw()),
                _ => break,
            }
            current = self.parents.get(&index).copied();
        }
        parts.reverse();
        parts.join("::")
    }

    /// Signedness of the integer unit a record describes, following modifiers.
    fn record_signed(&self, index: u32) -> bool {
        if index < 0x1000 {
            return self
                .primitive(index)
                .is_ok_and(|primitive| primitive_signed(primitive.kind));
        }
        match self.types.get(&index) {
            Some(TypeData::Primitive(primitive)) => primitive_signed(primitive.kind),
            Some(TypeData::Modifier(modifier)) => self.record_signed(modifier.underlying_type.0),
            Some(TypeData::Bitfield(bitfield)) => self.record_signed(bitfield.underlying_type.0),
            Some(TypeData::Enumeration(enumeration)) => {
                self.record_signed(enumeration.underlying_type.0)
            }
            _ => false,
        }
    }

    fn record_size(&self, index: u32, depth: usize) -> Result<u64> {
        if depth > 64 {
            return Err(Error::UnsupportedPdbRecord {
                detail: format!("type index {index:#x} nests too deeply"),
            });
        }
        if index < 0x1000 {
            let primitive = self.primitive(index)?;
            // A primitive with built-in indirection is a pointer to the primitive.
            return Ok(match primitive.indirection {
                Some(indirection) => indirection_size(indirection),
                None => primitive_size(primitive),
            });
        }
        match self.record(index)? {
            TypeData::Primitive(primitive) => Ok(primitive_size(*primitive)),
            TypeData::Pointer(pointer) => {
                let size = u64::from(pointer.attributes.size());
                Ok(if size == 0 { self.pointer_size } else { size })
            }
            TypeData::Modifier(modifier) => self.record_size(modifier.underlying_type.0, depth + 1),
            TypeData::Bitfield(bitfield) => self.record_size(bitfield.underlying_type.0, depth + 1),
            TypeData::Array(array) => match array.dimensions.last() {
                Some(total) => Ok(u64::from(*total)),
                None => Err(Error::UnsupportedPdbRecord {
                    detail: format!("array type index {index:#x} has no dimensions"),
                }),
            },
            TypeData::Class(class) => {
                if class.properties.forward_reference() {
                    if let Some(size) = self.definition_size(index)? {
                        return Ok(size);
                    }
                }
                Ok(class.size)
            }
            TypeData::Union(union) => {
                if union.properties.forward_reference() {
                    if let Some(size) = self.definition_size(index)? {
                        return Ok(size);
                    }
                }
                Ok(union.size)
            }
            TypeData::Enumeration(enumeration) => {
                self.record_size(enumeration.underlying_type.0, depth + 1)
            }
            other => Err(Error::UnsupportedPdbRecord {
                detail: format!(
                    "type index {index:#x} ({}) has no static size",
                    type_kind(other)
                ),
            }),
        }
    }

    fn spec(&self, index: u32) -> Result<Spec> {
        if index < 0x1000 {
            let primitive = self.primitive(index)?;
            return match primitive_kind(primitive.kind) {
                Some((kind, name, reason)) => Ok(Spec::Base {
                    name: name.to_string(),
                    size: primitive_size(primitive),
                    signed: primitive_signed(primitive.kind),
                    kind,
                    reason,
                }),
                None => Err(Error::UnsupportedPdbRecord {
                    detail: format!(
                        "primitive index {index:#x} has an unsupported kind {:?}",
                        primitive.kind
                    ),
                }),
            };
        }
        let data = self.record(index)?;
        let spec = match data {
            TypeData::Primitive(primitive) => match primitive_kind(primitive.kind) {
                Some((kind, name, reason)) => Spec::Base {
                    name: name.to_string(),
                    size: primitive_size(*primitive),
                    signed: primitive_signed(primitive.kind),
                    kind,
                    reason,
                },
                None => Spec::Unsupported(format!(
                    "primitive type index {index:#x} has an unsupported kind {:?}",
                    primitive.kind
                )),
            },
            TypeData::Pointer(pointer) => {
                let size = u64::from(pointer.attributes.size());
                let mut qualifiers = Vec::new();
                if pointer.attributes.is_const() {
                    qualifiers.push(Qualifier::Const);
                }
                if pointer.attributes.is_volatile() {
                    qualifiers.push(Qualifier::Volatile);
                }
                if pointer.attributes.is_restrict() {
                    qualifiers.push(Qualifier::Restrict);
                }
                let reference = match pointer.attributes.pointer_mode() {
                    PointerMode::LValueReference => Some(ReferenceKind::Lvalue),
                    PointerMode::RValueReference => Some(ReferenceKind::Rvalue),
                    _ => None,
                };
                Spec::Pointer {
                    target: pointer.underlying_type.0,
                    size: if size == 0 { self.pointer_size } else { size },
                    reference,
                    qualifiers,
                    member_pointer: pointer.attributes.pointer_to_member(),
                }
            }
            TypeData::Modifier(modifier) => {
                let mut qualifiers = Vec::new();
                if modifier.constant {
                    qualifiers.push(Qualifier::Const);
                }
                if modifier.volatile {
                    qualifiers.push(Qualifier::Volatile);
                }
                Spec::Qualified {
                    target: modifier.underlying_type.0,
                    qualifiers,
                }
            }
            TypeData::Array(array) => Spec::Array {
                element: array.element_type.0,
                dimensions: array.dimensions.clone(),
                stride: array.stride,
            },
            TypeData::Class(class) => self.composite_spec(
                index,
                CompositeKind::Struct,
                class.size,
                class.properties.forward_reference(),
                class.fields,
                class.name.raw(),
            )?,
            TypeData::Union(union) => self.composite_spec(
                index,
                CompositeKind::Union,
                union.size,
                union.properties.forward_reference(),
                Some(union.fields),
                union.name.raw(),
            )?,
            TypeData::Enumeration(enumeration) => {
                let underlying = enumeration.underlying_type.0;
                // The underlying type decides how a constant is interpreted, so its
                // width and signedness are read from it (following modifiers).
                let size = self.record_size(underlying, 0).unwrap_or(4);
                let signed = self.record_signed(underlying);
                let mut constants = Vec::new();
                for entry in self.field_entries(enumeration.fields)? {
                    if let FieldEntry::Enumerate { name, value } = entry {
                        constants.push((name, enum_value(value, size, signed)));
                    }
                }
                Spec::Enumeration {
                    underlying,
                    size,
                    signed,
                    constants,
                    forward: enumeration.properties.forward_reference(),
                }
            }
            TypeData::Procedure(procedure) => {
                let mut parameters = Vec::new();
                if let Some(TypeData::ArgumentList(list)) =
                    self.types.get(&procedure.argument_list.0)
                {
                    for argument in &list.arguments {
                        parameters.push(argument.0);
                    }
                }
                Spec::Procedure {
                    return_type: procedure.return_type.map(|index| index.0),
                    parameters,
                    calling_convention: calling_convention(procedure),
                }
            }
            other => Spec::Unsupported(format!(
                "type index {index:#x} is a {} record, which is not a type",
                type_kind(other)
            )),
        };
        Ok(spec)
    }

    fn composite_spec(
        &self,
        index: u32,
        kind: CompositeKind,
        size: u64,
        forward: bool,
        fields: Option<TypeIndex>,
        name: String,
    ) -> Result<Spec> {
        let mut members = Vec::new();
        let mut unsupported = None;
        let mut base_index = 0usize;
        let mut vftable_seen = false;
        if let Some(fields) = fields {
            // A field list this crate cannot decode would otherwise look like an
            // aggregate without members; report it instead.
            if !self.types.contains_key(&fields.0) && fields.0 >= 0x1000 {
                let detail = self
                    .unparsed
                    .get(&fields.0)
                    .cloned()
                    .unwrap_or_else(|| format!("field list {:#x} is missing", fields.0));
                unsupported.get_or_insert(format!(
                    "field list of type index {index:#x} cannot be decoded: {detail}"
                ));
                return Ok(Spec::Composite {
                    name,
                    kind,
                    size,
                    forward: false,
                    members,
                    unsupported,
                });
            }
            let entries = match self.field_entries(fields) {
                Ok(entries) => entries,
                Err(Error::UnsupportedPdbRecord { detail }) => {
                    return Ok(Spec::Composite {
                        name,
                        kind,
                        size,
                        forward: false,
                        members,
                        unsupported: Some(detail),
                    });
                }
                Err(error) => return Err(error),
            };
            for entry in entries {
                match entry {
                    FieldEntry::VirtualBase(base) => {
                        unsupported.get_or_insert_with(|| {
                            format!(
                                "virtual base class (type index {base:#x}) has no static ISF equivalent"
                            )
                        });
                    }
                    FieldEntry::Other(kind) => {
                        unsupported.get_or_insert_with(|| {
                            format!(
                                "field list entry {kind} of type index {index:#x} has no static ISF equivalent"
                            )
                        });
                    }
                    FieldEntry::Enumerate { .. } | FieldEntry::LayoutNeutral => {}
                    FieldEntry::Member(member) => {
                        if let MemberKind::BaseClass(_) = member.kind {
                            base_index += 1;
                            members.push(MemberSpec {
                                name: Some(format!("__base_{base_index}")),
                                ..member
                            });
                            continue;
                        }
                        if let MemberKind::VirtualFunctionTable = member.kind {
                            if vftable_seen {
                                continue;
                            }
                            vftable_seen = true;
                        }
                        members.push(member);
                    }
                }
            }
        }
        Ok(Spec::Composite {
            name,
            kind,
            size,
            forward,
            members,
            unsupported,
        })
    }

    /// Flatten a field list, following continuations.
    fn field_entries(&self, index: TypeIndex) -> Result<Vec<FieldEntry>> {
        let mut out = Vec::new();
        let mut current = Some(index.0);
        let mut guard = 0usize;
        while let Some(index) = current {
            guard += 1;
            if guard > 64 {
                return Err(Error::UnsupportedPdbRecord {
                    detail: "field list continuation chain is too long".to_string(),
                });
            }
            match self.types.get(&index) {
                Some(TypeData::FieldList(list)) => {
                    for field in &list.fields {
                        out.push(self.field_entry(field));
                    }
                    current = list.continuation.map(|next| next.0);
                }
                Some(_) => break,
                None if index >= 0x1000 => {
                    // Never truncate a member list silently.
                    let detail = self
                        .unparsed
                        .get(&index)
                        .cloned()
                        .unwrap_or_else(|| "record is missing".to_string());
                    return Err(Error::UnsupportedPdbRecord {
                        detail: format!("field list {index:#x} cannot be decoded: {detail}"),
                    });
                }
                None => break,
            }
        }
        Ok(out)
    }

    fn field_entry(&self, field: &TypeData<'t>) -> FieldEntry {
        match field {
            TypeData::Member(member) => {
                let name = member.name.raw();
                let name = if name.is_empty() { None } else { Some(name) };
                let kind = if member.field_type.0 < 0x1000 {
                    MemberKind::Data(member.field_type.0)
                } else {
                    match self.types.get(&member.field_type.0) {
                        Some(TypeData::Bitfield(bitfield)) => MemberKind::Bitfield {
                            underlying: bitfield.underlying_type.0,
                            position: u64::from(bitfield.position),
                            length: u64::from(bitfield.length),
                        },
                        Some(_) => MemberKind::Data(member.field_type.0),
                        None => MemberKind::Unsupported(format!(
                            "member type index {:#x} is missing",
                            member.field_type.0
                        )),
                    }
                };
                FieldEntry::Member(MemberSpec {
                    name,
                    offset: member.offset,
                    kind,
                })
            }
            TypeData::BaseClass(base_class) => FieldEntry::Member(MemberSpec {
                name: None,
                offset: u64::from(base_class.offset),
                kind: MemberKind::BaseClass(base_class.base_class.0),
            }),
            TypeData::VirtualBaseClass(virtual_base) => {
                FieldEntry::VirtualBase(virtual_base.base_class.0)
            }
            TypeData::VirtualFunctionTablePointer(_) => FieldEntry::Member(MemberSpec {
                name: Some("__vftable".to_string()),
                offset: 0,
                kind: MemberKind::VirtualFunctionTable,
            }),
            TypeData::Enumerate(enumerate) => FieldEntry::Enumerate {
                name: enumerate.name.raw(),
                value: enumerate.value,
            },
            TypeData::Nested(_)
            | TypeData::Method(_)
            | TypeData::MemberFunction(_)
            | TypeData::OverloadedMethod(_)
            | TypeData::StaticMember(_) => FieldEntry::LayoutNeutral,
            other => FieldEntry::Other(type_kind(other).to_string()),
        }
    }

    // -- resolution -------------------------------------------------------

    fn resolve_all(&mut self) -> Result<()> {
        let indices: Vec<u32> = self
            .types
            .iter()
            .filter(|(_, data)| is_resolvable(data))
            .map(|(index, _)| *index)
            .collect();
        for index in indices {
            self.type_for(index)?;
        }
        Ok(())
    }

    fn type_for(&mut self, index: u32) -> Result<TypeId> {
        if let Some(id) = self.cache.get(&index) {
            return Ok(*id);
        }
        // Primitive types with built-in indirection describe a pointer to the
        // primitive; the primitive itself is resolved first.
        let primitive = if index < 0x1000 {
            Some(self.primitive(index)?)
        } else {
            None
        };
        if let Some(primitive) = primitive {
            if let Some(indirection) = primitive.indirection {
                let base_index = index & !0xf00;
                let base = self.type_for(base_index)?;
                let size = indirection_size(indirection);
                let id = self.graph.pointer_to(
                    base,
                    if size == self.pointer_size {
                        None
                    } else {
                        Some(size)
                    },
                );
                self.cache.insert(index, id);
                return Ok(id);
            }
        }
        if let Some(TypeData::Bitfield(bitfield)) = self.types.get(&index) {
            let underlying = bitfield.underlying_type.0;
            let id = self.type_for(underlying)?;
            self.cache.insert(index, id);
            return Ok(id);
        }
        let id = match self.spec(index)? {
            Spec::Base {
                name,
                size,
                signed,
                kind,
                reason,
            } => self.graph.base(BaseRecord {
                name: BaseName::Source(name),
                size,
                signed,
                kind,
                alignment: None,
                unsupported_reason: reason,
                origin: Origin::Pdb { type_index: index },
            }),
            Spec::Pointer {
                target,
                size,
                reference,
                qualifiers,
                member_pointer,
            } => {
                if member_pointer {
                    let id = self.graph.base(BaseRecord {
                        name: BaseName::Source(self.qualified_name(index)),
                        size,
                        signed: false,
                        kind: BaseKind::Opaque,
                        alignment: None,
                        unsupported_reason: Some(
                            "pointer-to-member type has no static ISF equivalent".to_string(),
                        ),
                        origin: Origin::Pdb { type_index: index },
                    });
                    self.cache.insert(index, id);
                    return Ok(id);
                }
                // A pointer to a record this crate cannot decode keeps its own
                // layout; only the pointee identity is lost, so it becomes `void*`
                // rather than a guessed type.
                let target = match self.type_for(target) {
                    Ok(id) => id,
                    Err(Error::UnsupportedPdbRecord { .. }) => self.graph.void(),
                    Err(error) => return Err(error),
                };
                let mut node = match reference {
                    Some(kind) => self.graph.reference_to(target, kind),
                    None => self.graph.pointer_to(
                        target,
                        if size == self.pointer_size {
                            None
                        } else {
                            Some(size)
                        },
                    ),
                };
                for qualifier in qualifiers {
                    node = self.graph.qualified(node, qualifier);
                }
                node
            }
            Spec::Qualified { target, qualifiers } => {
                let mut node = self.type_for(target)?;
                for qualifier in qualifiers {
                    node = self.graph.qualified(node, qualifier);
                }
                node
            }
            Spec::Array {
                element,
                dimensions,
                stride,
            } => {
                let element_size = self.record_size(element, 0)?;
                let element_id = self.type_for(element)?;
                if let Some(stride) = stride {
                    if u64::from(stride) != element_size {
                        let id = self.graph.base(BaseRecord {
                            name: BaseName::Source(String::new()),
                            size: self.record_size(index, 0)?,
                            signed: false,
                            kind: BaseKind::Opaque,
                            alignment: None,
                            unsupported_reason: Some(format!(
                                "array stride {stride} differs from the element size {element_size}"
                            )),
                            origin: Origin::Pdb { type_index: index },
                        });
                        self.cache.insert(index, id);
                        return Ok(id);
                    }
                }
                if dimensions.is_empty() {
                    return Err(Error::UnsupportedPdbRecord {
                        detail: format!("array type index {index:#x} has no dimensions"),
                    });
                }
                let mut current = element_id;
                let mut previous = element_size;
                for dimension in dimensions {
                    let dimension = u64::from(dimension);
                    if previous == 0 || dimension % previous != 0 {
                        return Err(Error::UnsupportedPdbRecord {
                            detail: format!(
                                "array type index {index:#x} dimension {dimension} is not a multiple of {previous}"
                            ),
                        });
                    }
                    current = self.graph.array_of(current, dimension / previous);
                    previous = dimension;
                }
                current
            }
            Spec::Composite {
                name,
                kind,
                size,
                forward,
                members,
                unsupported,
            } => self.composite_type(
                index,
                CompositeParts {
                    name,
                    kind,
                    size,
                    forward,
                    members,
                    unsupported,
                },
            )?,
            Spec::Enumeration {
                underlying,
                size,
                signed,
                constants,
                forward,
                ..
            } => {
                if forward {
                    match self.definition_for(index)? {
                        Link::Single(definition) => {
                            let id = self.type_for(definition)?;
                            self.cache.insert(index, id);
                            return Ok(id);
                        }
                        Link::Missing => {}
                        Link::Ambiguous(reason) => {
                            let id = self.graph.base(BaseRecord {
                                name: BaseName::Source(self.qualified_name(index)),
                                size,
                                signed,
                                kind: BaseKind::Opaque,
                                alignment: None,
                                unsupported_reason: Some(reason),
                                origin: Origin::Pdb { type_index: index },
                            });
                            self.cache.insert(index, id);
                            return Ok(id);
                        }
                    }
                }
                let base = if forward {
                    None
                } else {
                    Some(self.type_for(underlying)?)
                };
                let domain = self.record_domain(index);
                self.graph.push(Node::Enum(EnumRecord {
                    name: Some(self.qualified_name(index)),
                    size,
                    base,
                    constants,
                    domain,
                    origin: Origin::Pdb { type_index: index },
                    unsupported: None,
                }))
            }
            Spec::Procedure {
                return_type,
                parameters,
                calling_convention,
            } => {
                let return_type = match return_type {
                    Some(index) => self.type_for(index)?,
                    None => self.graph.void(),
                };
                let mut resolved = Vec::new();
                for parameter in parameters {
                    let ty = self.type_for(parameter)?;
                    resolved.push((None, ty));
                }
                self.graph
                    .function(return_type, resolved, false, Some(calling_convention))
            }
            Spec::Unsupported(reason) => {
                return Err(Error::UnsupportedPdbRecord {
                    detail: format!("{reason} (in {})", self.path.display()),
                });
            }
        };
        self.cache.insert(index, id);
        Ok(id)
    }

    fn composite_type(&mut self, index: u32, spec: CompositeParts) -> Result<TypeId> {
        let CompositeParts {
            name,
            kind,
            size,
            forward,
            members,
            unsupported,
        } = spec;
        if forward {
            let reason = match self.definition_for(index)? {
                Link::Single(definition) => {
                    let id = self.type_for(definition)?;
                    self.cache.insert(index, id);
                    return Ok(id);
                }
                Link::Missing => None,
                Link::Ambiguous(reason) => Some(reason),
            };
            let id = self.graph.composite_slot();
            let qualified = self.qualified_name(index);
            let domain = self.record_domain(index);
            if let Ok(record) = self.graph.composite_mut(id) {
                record.name = Some(qualified);
                record.kind = kind;
                record.domain = domain;
                record.origin = Origin::Pdb { type_index: index };
                record.incomplete = true;
                record.unsupported = reason;
            }
            self.cache.insert(index, id);
            return Ok(id);
        }
        let id = self.graph.composite_slot();
        self.cache.insert(index, id);
        let mut built = Vec::new();
        let mut unsupported = unsupported;
        // Room available to each member inside this record, used to disambiguate
        // declarations whose definitions disagree.
        let mut spans = vec![None; members.len()];
        for position in 0..members.len() {
            let offset = members[position].offset;
            let mut next = size;
            for later in &members[position + 1..] {
                if later.offset > offset {
                    next = later.offset;
                    break;
                }
            }
            spans[position] = next.checked_sub(offset).filter(|span| *span > 0);
        }
        for (position, member) in members.into_iter().enumerate() {
            match member.kind {
                MemberKind::Data(type_index) => {
                    let mut ty = self.type_for(type_index)?;
                    if self.is_unresolved_declaration(ty) {
                        if let Some(resolved) =
                            self.resolve_declaration_by_span(type_index, spans[position])?
                        {
                            ty = resolved;
                        }
                    }
                    built.push(Member {
                        anonymous: member.name.is_none(),
                        name: member.name,
                        offset: member.offset,
                        ty,
                        bitfield: None,
                    });
                }
                MemberKind::Bitfield {
                    underlying,
                    position,
                    length,
                } => {
                    if length == 0 {
                        continue;
                    }
                    let declared = self.type_for(underlying)?;
                    let signed = self.graph.base_signed(declared).unwrap_or(false);
                    let start = member
                        .offset
                        .checked_mul(8)
                        .and_then(|offset| offset.checked_add(position))
                        .ok_or_else(|| Error::Overflow {
                            location: format!("PDB type index {index:#x}"),
                            what: "bit-field start".to_string(),
                        })?;
                    built.push(self.graph.bitfield_member(
                        member.name,
                        &Origin::Pdb { type_index: index },
                        start,
                        length,
                        declared,
                        signed,
                    )?);
                }
                MemberKind::BaseClass(base) => {
                    let ty = self.type_for(base)?;
                    built.push(Member {
                        anonymous: false,
                        name: member.name,
                        offset: member.offset,
                        ty,
                        bitfield: None,
                    });
                }
                MemberKind::VirtualFunctionTable => {
                    let ty = self.graph.pointer_base();
                    built.push(Member {
                        anonymous: false,
                        name: member.name,
                        offset: member.offset,
                        ty,
                        bitfield: None,
                    });
                }
                MemberKind::Unsupported(reason) => {
                    unsupported.get_or_insert(reason);
                }
            }
        }
        let domain = self.record_domain(index);
        if let Ok(record) = self.graph.composite_mut(id) {
            record.name = Some(name);
            record.kind = kind;
            record.size = Some(size);
            record.domain = domain;
            record.origin = Origin::Pdb { type_index: index };
            record.incomplete = false;
            record.members = built;
            record.unsupported = unsupported;
        }
        Ok(id)
    }

    /// Complete definitions that could stand in for a forward declaration.
    fn definition_candidates(&self, index: u32) -> Result<Vec<u32>> {
        let data = self.record(index)?;
        let (name, unique) = match data {
            TypeData::Class(class) => (class.name.raw(), class.unique_name.map(|name| name.raw())),
            TypeData::Union(union) => (union.name.raw(), union.unique_name.map(|name| name.raw())),
            TypeData::Enumeration(enumeration) => (
                enumeration.name.raw(),
                enumeration.unique_name.map(|name| name.raw()),
            ),
            _ => return Ok(Vec::new()),
        };
        let mut candidates = Vec::new();
        if unique.is_some() {
            if let Some(found) = self.definitions.get(&(unique, name.clone())) {
                candidates.extend(found.iter().copied());
            }
        }
        if candidates.is_empty() {
            if let Some(found) = self.definitions.get(&(None, name)) {
                candidates.extend(found.iter().copied());
            }
        }
        Ok(candidates)
    }

    /// Resolve a forward declaration to its complete definition.
    ///
    /// Candidates that describe the same layout are the same type and merge; a name
    /// claimed by definitions with different layouts is reported and the declaration
    /// stays unresolved, so no definition is silently preferred.
    fn definition_for(&mut self, index: u32) -> Result<Link> {
        let candidates = self.scoped_candidates(index, self.definition_candidates(index)?);
        match candidates.len() {
            0 => Ok(Link::Missing),
            1 => Ok(Link::Single(candidates[0])),
            _ => {
                let mut resolved = Vec::with_capacity(candidates.len());
                for candidate in &candidates {
                    resolved.push((*candidate, self.type_for(*candidate)?));
                }
                let first = resolved[0].1;
                if resolved
                    .iter()
                    .all(|(_, id)| self.graph.equivalent(first, *id))
                {
                    return Ok(Link::Single(candidates[0]));
                }
                let name = self.record_name(index).unwrap_or_default();
                Ok(Link::Ambiguous(format!(
                    "type indices {} define `{name}` with different layouts, so this declaration stays unresolved",
                    candidates
                        .iter()
                        .map(|index| format!("{index:#x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )))
            }
        }
    }

    /// Size stated by a complete definition record.
    fn definition_record_size(&self, index: u32) -> Option<u64> {
        match self.types.get(&index) {
            Some(TypeData::Class(class)) => Some(class.size),
            Some(TypeData::Union(union)) => Some(union.size),
            _ => None,
        }
    }

    /// True when `id` is a declaration that could not be linked to a definition.
    fn is_unresolved_declaration(&self, id: TypeId) -> bool {
        matches!(self.graph.node(id), Node::Composite(record) if record.incomplete)
    }

    /// Pick one of several competing definitions using the room the containing
    /// aggregate gives the member.
    ///
    /// A by-value member inside a record whose offsets are known has a known span
    /// (up to the next member, or the end of the record). That span is evidence from
    /// the debug information, so a definition that exactly fills it is not a guess.
    fn resolve_declaration_by_span(
        &mut self,
        index: u32,
        span: Option<u64>,
    ) -> Result<Option<TypeId>> {
        let Some(span) = span else {
            return Ok(None);
        };
        if index < 0x1000 {
            return Ok(None);
        }
        let candidates = self.definition_candidates(index)?;
        if candidates.len() < 2 {
            return Ok(None);
        }
        let mut exact = Vec::new();
        let mut smaller = Vec::new();
        for candidate in candidates {
            match self.definition_record_size(candidate) {
                Some(size) if size == span => exact.push(candidate),
                Some(size) if size <= span => smaller.push(candidate),
                _ => {}
            }
        }
        let chosen = match exact.len() {
            1 => Some(exact[0]),
            0 if smaller.len() == 1 => Some(smaller[0]),
            _ => None,
        };
        match chosen {
            Some(candidate) => {
                let id = self.type_for(candidate)?;
                self.cache.insert(index, id);
                Ok(Some(id))
            }
            None => Ok(None),
        }
    }

    /// Size shared by every candidate definition of a forward declaration.
    fn definition_size(&self, index: u32) -> Result<Option<u64>> {
        let candidates = self.scoped_candidates(index, self.definition_candidates(index)?);
        let mut sizes = BTreeSet::new();
        for candidate in candidates {
            match self.types.get(&candidate) {
                Some(TypeData::Class(class)) => {
                    sizes.insert(class.size);
                }
                Some(TypeData::Union(union)) => {
                    sizes.insert(union.size);
                }
                _ => {}
            }
        }
        match sizes.len() {
            0 => Ok(None),
            1 => Ok(sizes.into_iter().next()),
            _ => Err(Error::UnsupportedPdbRecord {
                detail: format!(
                    "forward declaration {index:#x} has candidate definitions of different sizes"
                ),
            }),
        }
    }

    fn procedure_signature(&mut self, type_index: u32) -> Result<FunctionRecord> {
        match self.spec(type_index)? {
            Spec::Procedure {
                return_type,
                parameters,
                calling_convention,
            } => {
                let return_type = match return_type {
                    Some(index) => self.type_for(index)?,
                    None => self.graph.void(),
                };
                let mut resolved = Vec::new();
                for parameter in parameters {
                    resolved.push((None, self.type_for(parameter)?));
                }
                Ok(FunctionRecord {
                    return_type,
                    parameters: resolved,
                    variadic: false,
                    calling_convention: Some(calling_convention),
                })
            }
            _ => Err(Error::UnsupportedPdbRecord {
                detail: format!("type index {type_index:#x} is not a procedure signature"),
            }),
        }
    }
}

fn is_resolvable(data: &TypeData<'_>) -> bool {
    matches!(
        data,
        TypeData::Primitive(_)
            | TypeData::Pointer(_)
            | TypeData::Modifier(_)
            | TypeData::Array(_)
            | TypeData::Class(_)
            | TypeData::Union(_)
            | TypeData::Enumeration(_)
            | TypeData::Procedure(_)
            | TypeData::Bitfield(_)
    )
}

fn type_kind(data: &TypeData<'_>) -> &'static str {
    match data {
        TypeData::Primitive(_) => "primitive",
        TypeData::Class(_) => "class",
        TypeData::Member(_) => "member",
        TypeData::MemberFunction(_) => "member function",
        TypeData::OverloadedMethod(_) => "overloaded method",
        TypeData::Method(_) => "method",
        TypeData::StaticMember(_) => "static member",
        TypeData::Nested(_) => "nested type",
        TypeData::BaseClass(_) => "base class",
        TypeData::VirtualBaseClass(_) => "virtual base class",
        TypeData::VirtualFunctionTablePointer(_) => "vtable pointer",
        TypeData::Procedure(_) => "procedure",
        TypeData::Pointer(_) => "pointer",
        TypeData::Modifier(_) => "modifier",
        TypeData::Enumeration(_) => "enumeration",
        TypeData::Enumerate(_) => "enumerator",
        TypeData::Array(_) => "array",
        TypeData::Union(_) => "union",
        TypeData::Bitfield(_) => "bit-field",
        TypeData::FieldList(_) => "field list",
        TypeData::ArgumentList(_) => "argument list",
        TypeData::MethodList(_) => "method list",
        _ => "unknown record",
    }
}

fn primitive_size(primitive: PrimitiveType) -> u64 {
    use PrimitiveKind as K;
    match primitive.kind {
        K::NoType | K::Void => 0,
        K::Char | K::UChar | K::RChar | K::I8 | K::U8 | K::Bool8 => 1,
        K::WChar | K::RChar16 | K::Short | K::UShort | K::I16 | K::U16 | K::F16 | K::Bool16 => 2,
        K::HRESULT
        | K::Long
        | K::ULong
        | K::I32
        | K::U32
        | K::F32
        | K::F32PP
        | K::Bool32
        | K::RChar32 => 4,
        K::Quad | K::UQuad | K::I64 | K::U64 | K::F64 | K::Bool64 => 8,
        K::Octa | K::UOcta | K::I128 | K::U128 | K::F128 | K::Complex128 => 16,
        K::F48 => 6,
        K::F80 | K::Complex80 => 10,
        K::Complex32 => 8,
        K::Complex64 => 16,
        _ => 0,
    }
}

fn primitive_signed(kind: PrimitiveKind) -> bool {
    use PrimitiveKind as K;
    matches!(
        kind,
        K::Char
            | K::RChar
            | K::I8
            | K::Short
            | K::I16
            | K::Long
            | K::I32
            | K::Quad
            | K::I64
            | K::Octa
            | K::I128
    )
}

fn primitive_kind(kind: PrimitiveKind) -> Option<(BaseKind, &'static str, Option<String>)> {
    use PrimitiveKind as K;
    let mapped = match kind {
        K::NoType | K::Void => (BaseKind::Void, "void", None),
        K::Char | K::RChar => (BaseKind::Char, "char", None),
        K::UChar => (BaseKind::Char, "unsigned char", None),
        K::WChar | K::RChar16 => (BaseKind::Char, "wchar_t", None),
        K::RChar32 => (BaseKind::Char, "char32_t", None),
        K::I8 => (BaseKind::Int, "signed char", None),
        K::U8 => (BaseKind::Int, "unsigned char", None),
        K::Short => (BaseKind::Int, "short", None),
        K::UShort => (BaseKind::Int, "unsigned short", None),
        K::I16 => (BaseKind::Int, "short", None),
        K::U16 => (BaseKind::Int, "unsigned short", None),
        K::Long => (BaseKind::Int, "long", None),
        K::ULong => (BaseKind::Int, "unsigned long", None),
        K::I32 => (BaseKind::Int, "int", None),
        K::U32 => (BaseKind::Int, "unsigned int", None),
        K::Quad => (BaseKind::Int, "long long", None),
        K::UQuad => (BaseKind::Int, "unsigned long long", None),
        K::I64 => (BaseKind::Int, "__int64", None),
        K::U64 => (BaseKind::Int, "unsigned __int64", None),
        K::Octa | K::I128 => (BaseKind::Int, "__int128", None),
        K::UOcta | K::U128 => (BaseKind::Int, "unsigned __int128", None),
        K::F16 => (BaseKind::Float, "float16", None),
        K::F32 | K::F32PP => (BaseKind::Float, "float", None),
        K::F48 | K::F80 => (BaseKind::Float, "long double", None),
        K::F64 => (BaseKind::Float, "double", None),
        K::F128 => (BaseKind::Float, "float128", None),
        K::Complex32 | K::Complex64 | K::Complex80 | K::Complex128 => {
            (BaseKind::Float, "complex", None)
        }
        K::Bool8 | K::Bool16 | K::Bool32 | K::Bool64 => (BaseKind::Bool, "bool", None),
        K::HRESULT => (BaseKind::Int, "HRESULT", None),
        _ => return None,
    };
    Some(mapped)
}

fn enum_value(value: Variant, size: u64, signed: bool) -> IntValue {
    // The width and sign of the stored value come from the numeric leaf: a one-byte
    // constant is always `LF_CHAR`, so `Variant::U8` carries a signed byte.
    let raw: i128 = match value {
        Variant::U8(value) => i128::from(value as i8),
        Variant::U16(value) => i128::from(value),
        Variant::U32(value) => i128::from(value),
        Variant::U64(value) => i128::from(value),
        Variant::I8(value) => i128::from(value),
        Variant::I16(value) => i128::from(value),
        Variant::I32(value) => i128::from(value),
        Variant::I64(value) => i128::from(value),
    };
    let bits = size.saturating_mul(8).min(64);
    if bits == 0 {
        return IntValue::Signed(0);
    }
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let raw = (raw as u64) & mask;
    if signed {
        let shift = 64 - bits;
        IntValue::Signed(((raw << shift) as i64) >> shift)
    } else {
        IntValue::Unsigned(raw)
    }
}

fn calling_convention(procedure: &pdb::ProcedureType) -> String {
    match procedure.attributes.calling_convention() {
        0x00 => "near_cdecl".to_string(),
        0x04 => "near_fastcall".to_string(),
        0x07 => "near_stdcall".to_string(),
        0x0b => "near_thiscall".to_string(),
        0x16 => "near_vectorcall".to_string(),
        other => format!("0x{other:02x}"),
    }
}

// ---------------------------------------------------------------------------
// Symbols
// ---------------------------------------------------------------------------

enum PendingSymbol {
    Data {
        name: String,
        type_index: u32,
        offset: PdbInternalSectionOffset,
    },
    Procedure {
        name: String,
        type_index: u32,
        offset: PdbInternalSectionOffset,
    },
    Public {
        name: String,
        offset: PdbInternalSectionOffset,
        function: bool,
    },
    Alias {
        name: String,
        type_index: u32,
        module: Option<usize>,
    },
}

/// Type indices one module's symbols refer to, plus its path-free label.
struct ModuleTypes {
    index: usize,
    domain: String,
    types: BTreeSet<u32>,
}

/// Symbols and module/type associations gathered before type resolution.
struct Pending {
    symbols: Vec<PendingSymbol>,
    modules: Vec<ModuleTypes>,
}

/// Walk every symbol stream once, collecting the symbols to publish and the
/// module/type associations that give type records their name domain.
fn collect_pending<'s, S: Read + Seek + std::fmt::Debug + 's>(
    path: &Path,
    pdb: &mut PDB<'s, S>,
) -> Result<Pending> {
    let mut symbols: Vec<PendingSymbol> = Vec::new();
    {
        let globals = pdb.global_symbols().map_err(|e| pdb_error(path, e))?;
        let mut iter = globals.iter();
        while let Some(symbol) = iter.next().map_err(|e| pdb_error(path, e))? {
            match symbol.parse() {
                Ok(data) => push_symbol(&mut symbols, data, None),
                Err(error) if skippable_symbol(&error) => {}
                Err(error) => return Err(pdb_error(path, error)),
            }
        }
    }
    let mut modules: Vec<ModuleTypes> = Vec::new();
    {
        let information = pdb.debug_information().map_err(|e| pdb_error(path, e))?;
        let mut iterator = information.modules().map_err(|e| pdb_error(path, e))?;
        let mut position = 0usize;
        while let Some(module) = iterator.next().map_err(|e| pdb_error(path, e))? {
            let index = position;
            position += 1;
            let domain = source_basename(&module.module_name());
            let Some(info) = pdb.module_info(&module).map_err(|e| pdb_error(path, e))? else {
                continue;
            };
            let mut types: BTreeSet<u32> = BTreeSet::new();
            let mut iter = info.symbols().map_err(|e| pdb_error(path, e))?;
            let mut inside_procedure = false;
            while let Some(symbol) = iter.next().map_err(|e| pdb_error(path, e))? {
                let data = match symbol.parse() {
                    Ok(data) => data,
                    Err(error) if skippable_symbol(&error) => continue,
                    Err(error) => return Err(pdb_error(path, error)),
                };
                let is_procedure = matches!(&data, pdb::SymbolData::Procedure(_));
                let is_scope_end = matches!(&data, pdb::SymbolData::ScopeEnd);
                let local = match &data {
                    pdb::SymbolData::Data(data) => !data.global && inside_procedure,
                    _ => false,
                };
                if is_procedure {
                    inside_procedure = true;
                }
                if is_scope_end {
                    inside_procedure = false;
                }
                note_type(&data, &mut types);
                if !local {
                    push_symbol(&mut symbols, data, Some(index));
                }
            }
            modules.push(ModuleTypes {
                index,
                domain,
                types,
            });
        }
    }
    Ok(Pending { symbols, modules })
}

/// Record the type indices a symbol refers to.
///
/// Locals and register variables count: a type reached only through a local
/// variable is still used by that compilation unit, which is what the name domain
/// has to reflect.
fn note_type(symbol: &pdb::SymbolData<'_>, out: &mut BTreeSet<u32>) {
    match symbol {
        pdb::SymbolData::Data(data) => {
            out.insert(data.type_index.0);
        }
        pdb::SymbolData::Procedure(procedure) => {
            out.insert(procedure.type_index.0);
        }
        pdb::SymbolData::UserDefinedType(alias) => {
            out.insert(alias.type_index.0);
        }
        pdb::SymbolData::Local(local) => {
            out.insert(local.type_index.0);
        }
        pdb::SymbolData::RegisterVariable(variable) => {
            out.insert(variable.type_index.0);
        }
        pdb::SymbolData::MultiRegisterVariable(variable) => {
            out.insert(variable.type_index.0);
        }
        pdb::SymbolData::Constant(constant) => {
            out.insert(constant.type_index.0);
        }
        _ => {}
    }
}

/// Path-free last component of a file or module name.
fn source_basename(name: &str) -> String {
    let trimmed = name.trim();
    let base = trimmed
        .rsplit(|character| ['/', '\\', ')'].contains(&character))
        .next()
        .unwrap_or(trimmed)
        .trim();
    if base.is_empty() || base == "." || base == ".." {
        "module".to_string()
    } else {
        base.to_string()
    }
}

/// Publish the collected symbols once types are resolved.
fn apply_pending<'t>(
    resolver: &mut Resolver<'t>,
    pending: Pending,
    addresses: Option<(&AddressMap<'_>, u64)>,
    detail: crate::Detail,
) -> Result<()> {
    for symbol in pending.symbols {
        match symbol {
            PendingSymbol::Alias {
                name,
                type_index,
                module,
            } => {
                if name.is_empty() || resolver.record_name(type_index).as_deref() == Some(&name) {
                    continue;
                }
                let target = match resolver.type_for(type_index) {
                    Ok(target) => target,
                    Err(Error::UnsupportedPdbRecord { .. }) => continue,
                    Err(error) => return Err(error),
                };
                let domain =
                    module.and_then(|module| resolver.module_domains.get(&module).cloned());
                let slot = resolver
                    .graph
                    .typedef_slot(name, Origin::Pdb { type_index });
                resolver.graph.set_domain(slot, domain)?;
                resolver.graph.set_typedef_target(slot, target)?;
            }
            PendingSymbol::Data {
                name,
                type_index,
                offset,
            } => {
                if name.is_empty() || !detail.wants_symbols() {
                    continue;
                }
                let ty = if type_index == 0 {
                    None
                } else {
                    match resolver.type_for(type_index) {
                        Ok(ty) => Some(ty),
                        Err(Error::UnsupportedPdbRecord { .. }) => None,
                        Err(error) => return Err(error),
                    }
                };
                let address = absolute_address(offset, addresses);
                insert_symbol(&mut resolver.symbols, name, address, ty);
            }
            PendingSymbol::Public {
                name,
                offset,
                function,
            } => {
                if name.is_empty() || function || !detail.wants_symbols() {
                    continue;
                }
                let address = absolute_address(offset, addresses);
                insert_symbol(&mut resolver.symbols, name, address, None);
            }
            PendingSymbol::Procedure {
                name,
                type_index,
                offset,
            } => {
                if name.is_empty() || !detail.wants_functions() {
                    continue;
                }
                let address = absolute_address(offset, addresses);
                let signature = match resolver.procedure_signature(type_index) {
                    Ok(signature) => signature,
                    Err(Error::UnsupportedPdbRecord { .. }) => FunctionRecord {
                        return_type: resolver.graph.void(),
                        parameters: Vec::new(),
                        variadic: false,
                        calling_convention: None,
                    },
                    Err(error) => return Err(error),
                };
                insert_function(
                    &mut resolver.functions,
                    name,
                    GlobalFunction { address, signature },
                );
            }
        }
    }
    Ok(())
}

fn push_symbol<'t>(
    pending: &mut Vec<PendingSymbol>,
    data: pdb::SymbolData<'t>,
    module: Option<usize>,
) {
    match data {
        pdb::SymbolData::Data(data) => pending.push(PendingSymbol::Data {
            name: data.name.raw(),
            type_index: data.type_index.0,
            offset: data.offset,
        }),
        pdb::SymbolData::Procedure(procedure) => pending.push(PendingSymbol::Procedure {
            name: procedure.name.raw(),
            type_index: procedure.type_index.0,
            offset: procedure.offset,
        }),
        pdb::SymbolData::Public(public) => pending.push(PendingSymbol::Public {
            name: public.name.raw(),
            offset: public.offset,
            function: public.function,
        }),
        pdb::SymbolData::UserDefinedType(alias) => pending.push(PendingSymbol::Alias {
            name: alias.name.raw(),
            type_index: alias.type_index.0,
            module,
        }),
        _ => {}
    }
}

fn absolute_address(
    offset: PdbInternalSectionOffset,
    addresses: Option<(&AddressMap<'_>, u64)>,
) -> Option<u64> {
    let (address_map, image_base) = addresses?;
    let rva = offset.to_rva(address_map)?;
    image_base.checked_add(u64::from(rva.0))
}

fn insert_symbol(
    symbols: &mut BTreeMap<String, GlobalSymbol>,
    name: String,
    address: Option<u64>,
    ty: Option<TypeId>,
) {
    match symbols.get(&name) {
        Some(existing) => {
            let better = (existing.ty.is_none() && ty.is_some())
                || (existing.address.is_none() && address.is_some());
            if better {
                symbols.insert(name, GlobalSymbol { address, ty });
            }
        }
        None => {
            symbols.insert(name, GlobalSymbol { address, ty });
        }
    }
}

fn insert_function(
    functions: &mut BTreeMap<String, GlobalFunction>,
    name: String,
    function: GlobalFunction,
) {
    match functions.get(&name) {
        Some(existing) if existing.address.is_some() && function.address.is_none() => {}
        Some(_) => {}
        None => {
            functions.insert(name, function);
        }
    }
}
