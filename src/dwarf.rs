//! Native DWARF frontend: ELF and Mach-O debug information into the normalized
//! type graph.
//!
//! The frontend reads DWARF 4 and DWARF 5 compilation and type units with
//! `gimli`, applies relocations for relocatable objects, records every DIE under
//! a stable identity (section plus absolute offset), and solves references in two
//! passes: every aggregate is registered before its members are resolved, so
//! recursive records work, and cross-unit, `DW_AT_specification` and
//! `DW_AT_abstract_origin` references all resolve through the same index.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use gimli::{
    AttributeValue, DwAt, DwTag, Dwarf, EndianSlice, EntriesTreeNode, Expression, Operation,
    Reader as GimliReader, Relocate, RelocateReader, RunTimeEndian, SectionId, Unit, UnitOffset,
    UnitSectionOffset, UnitType, constants,
};
use object::read::macho::FatArch;
use object::{
    BinaryFormat, Object, ObjectKind, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget,
};

use crate::error::{Error, Result};
use crate::isf::{
    BaseKind, CompositeKind, Endian, IntValue, IsfDocument, Qualifier, ReferenceKind, Target,
};
use crate::normalize::{
    BaseName, BaseRecord, EnumRecord, FunctionRecord, GlobalFunction, GlobalSymbol, Member, Node,
    Origin, TypeGraph, TypeId,
};

/// Sections `Dwarf::load` asks for.
const SECTION_IDS: [SectionId; 16] = [
    SectionId::DebugAbbrev,
    SectionId::DebugAddr,
    SectionId::DebugAranges,
    SectionId::DebugInfo,
    SectionId::DebugLine,
    SectionId::DebugLineStr,
    SectionId::DebugMacinfo,
    SectionId::DebugMacro,
    SectionId::DebugNames,
    SectionId::DebugStr,
    SectionId::DebugStrOffsets,
    SectionId::DebugTypes,
    SectionId::DebugLoc,
    SectionId::DebugLocLists,
    SectionId::DebugRanges,
    SectionId::DebugRngLists,
];

/// Hard limit on nesting so that adversarial input cannot exhaust the stack.
const MAX_DIE_DEPTH: usize = 512;

type Slice<'a> = EndianSlice<'a, RunTimeEndian>;
type SectionReader<'a> = RelocateReader<Slice<'a>, SectionRelocator>;
type DwarfReader<'a> = Dwarf<SectionReader<'a>>;

/// Convert one ELF or Mach-O input.
pub(crate) fn convert(
    image: &Path,
    debug_file: Option<&Path>,
    architecture: Option<&str>,
    types_only: bool,
) -> Result<IsfDocument> {
    let image_bytes = std::fs::read(image).map_err(|e| Error::io(image, e))?;
    let (image_slice, slice_arch) = select_slice(&image_bytes, architecture, image)?;
    let image_file = object::File::parse(image_slice).map_err(|e| Error::UnsupportedContainer {
        path: image.into(),
        detail: e.to_string(),
    })?;
    let arch = architecture_name(image_file.architecture()).ok_or_else(|| {
        Error::UnsupportedContainer {
            path: image.into(),
            detail: format!(
                "architecture {:?} is not supported",
                image_file.architecture()
            ),
        }
    })?;
    if let Some(requested) = architecture {
        let candidates = slice_arch.clone().unwrap_or_else(|| vec![arch.clone()]);
        if requested != arch {
            return Err(Error::UnknownArchitecture {
                path: image.into(),
                requested: requested.to_string(),
                candidates,
            });
        }
    }
    match image_file.format() {
        BinaryFormat::Elf | BinaryFormat::MachO => {}
        other => {
            return Err(Error::UnsupportedContainer {
                path: image.into(),
                detail: format!("{other:?} has no DWARF debug information"),
            });
        }
    }
    if image_file.kind() == ObjectKind::Relocatable && !types_only {
        return Err(Error::UnlinkedImage { path: image.into() });
    }
    let endian = if image_file.is_little_endian() {
        Endian::Little
    } else {
        Endian::Big
    };
    let pointer_size = if image_file.is_64() { 8 } else { 4 };

    // A separate debug file replaces the image as the source of debug sections.
    let separate: Option<(Vec<u8>, PathBuf)> = match debug_file {
        Some(path) => Some((read_debug_file(path, &image_file, image)?, path.into())),
        None => None,
    };
    let (debug_object, debug_path): (object::File<'_>, PathBuf) = match &separate {
        Some((bytes, path)) => {
            let parsed = object::File::parse(&bytes[..]).map_err(|e| Error::Corrupt {
                path: path.clone(),
                detail: e.to_string(),
            })?;
            (parsed, path.clone())
        }
        None => (
            object::File::parse(image_slice).map_err(|e| Error::UnsupportedContainer {
                path: image.into(),
                detail: e.to_string(),
            })?,
            image.into(),
        ),
    };
    if separate.is_some() {
        verify_companion(&image_file, &debug_object, image, &debug_path)?;
    }

    let store = load_sections(&debug_object, &debug_path)?;
    if store.data.is_empty() {
        return Err(Error::NoDebugInfo { path: debug_path });
    }
    let run_time_endian = match endian {
        Endian::Little => RunTimeEndian::Little,
        Endian::Big => RunTimeEndian::Big,
    };
    let dwarf = Dwarf::load(|id: SectionId| {
        let name = id.name();
        let empty: &[u8] = &[];
        let data = store.data.get(name).map(|c| c.as_ref()).unwrap_or(empty);
        let relocator = store
            .relocations
            .get(name)
            .cloned()
            .unwrap_or_else(SectionRelocator::empty);
        Ok::<SectionReader<'_>, Error>(RelocateReader::new(
            EndianSlice::new(data, run_time_endian),
            relocator,
        ))
    })?;

    let mut units: Vec<Unit<SectionReader<'_>>> = Vec::new();
    let mut headers = dwarf.units();
    while let Some(header) = headers.next().map_err(|e| corrupt(&debug_path, e))? {
        register_unit(&dwarf, header, &debug_path, &mut units)?;
    }
    let mut type_headers = dwarf.type_units();
    while let Some(header) = type_headers.next().map_err(|e| corrupt(&debug_path, e))? {
        register_unit(&dwarf, header, &debug_path, &mut units)?;
    }
    if units.is_empty() {
        return Err(Error::NoDebugInfo { path: debug_path });
    }

    let mut frontend = Frontend {
        path: debug_path,
        dwarf,
        units,
        index: BTreeMap::new(),
        graph: TypeGraph::new(Target {
            architecture: arch,
            pointer_size,
            endian,
        }),
        cache: BTreeMap::new(),
        definitions: BTreeMap::new(),
        specified_by: BTreeMap::new(),
        signatures: BTreeMap::new(),
        unit_domains: Vec::new(),
        symbols: BTreeMap::new(),
        functions: BTreeMap::new(),
    };
    frontend.collect_all()?;
    frontend.resolve_all()?;
    if !types_only {
        frontend.collect_globals()?;
    }
    let Frontend {
        graph,
        symbols,
        functions,
        ..
    } = frontend;
    let document = graph.emit(None, symbols, functions)?;
    document.validate()?;
    Ok(document)
}

/// Outcome of linking a declaration to its definition.
enum Link {
    /// Exactly one definition was found.
    Single(DieKey),
    /// No definition exists in this file.
    Missing,
    /// Several definitions claim the declaration.
    Ambiguous(String),
}

/// Last path component of a source file name, so no absolute path reaches the output.
fn source_basename(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    let base = trimmed
        .rsplit(|character| character == '/' || character == '\\')
        .next()
        .unwrap_or(trimmed)
        .trim();
    if base.is_empty() || base == "." || base == ".." {
        None
    } else {
        Some(base.to_string())
    }
}

fn corrupt(path: &Path, error: gimli::Error) -> Error {
    Error::Corrupt {
        path: path.into(),
        detail: error.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Container and architecture selection
// ---------------------------------------------------------------------------

fn architecture_name(arch: object::Architecture) -> Option<String> {
    use object::Architecture;
    let name = match arch {
        Architecture::Aarch64 => "aarch64",
        Architecture::Arm => "arm",
        Architecture::I386 => "i386",
        Architecture::X86_64 => "x86_64",
        Architecture::PowerPc => "powerpc",
        Architecture::PowerPc64 => "powerpc64",
        Architecture::Riscv32 => "riscv32",
        Architecture::Riscv64 => "riscv64",
        Architecture::S390x => "s390x",
        Architecture::Mips => "mips",
        Architecture::Mips64 => "mips64",
        Architecture::LoongArch64 => "loongarch64",
        Architecture::Unknown => return None,
        other => return Some(format!("{other:?}").to_lowercase()),
    };
    Some(name.to_string())
}

/// Select the requested architecture slice from a Mach-O universal binary.
fn select_slice<'a>(
    bytes: &'a [u8],
    requested: Option<&str>,
    path: &Path,
) -> Result<(&'a [u8], Option<Vec<String>>)> {
    use object::read::macho::{MachOFatFile32, MachOFatFile64};
    let kind = object::FileKind::parse(bytes).map_err(|e| Error::UnsupportedContainer {
        path: path.into(),
        detail: e.to_string(),
    })?;
    let arches: Vec<(String, u64, u64)> = match kind {
        object::FileKind::MachOFat32 => {
            let fat = MachOFatFile32::parse(bytes).map_err(|e| Error::Corrupt {
                path: path.into(),
                detail: e.to_string(),
            })?;
            fat.arches()
                .iter()
                .map(|arch| {
                    (
                        architecture_name(arch.architecture())
                            .unwrap_or_else(|| "unknown".to_string()),
                        arch.offset().into(),
                        arch.size().into(),
                    )
                })
                .collect()
        }
        object::FileKind::MachOFat64 => {
            let fat = MachOFatFile64::parse(bytes).map_err(|e| Error::Corrupt {
                path: path.into(),
                detail: e.to_string(),
            })?;
            fat.arches()
                .iter()
                .map(|arch| {
                    (
                        architecture_name(arch.architecture())
                            .unwrap_or_else(|| "unknown".to_string()),
                        arch.offset().into(),
                        arch.size().into(),
                    )
                })
                .collect()
        }
        _ => return Ok((bytes, None)),
    };
    let candidates: Vec<String> = arches.iter().map(|(name, _, _)| name.clone()).collect();
    let chosen = match requested {
        Some(wanted) => arches
            .iter()
            .find(|(name, _, _)| name == wanted)
            .ok_or_else(|| Error::UnknownArchitecture {
                path: path.into(),
                requested: wanted.to_string(),
                candidates: candidates.clone(),
            })?,
        None if arches.len() == 1 => &arches[0],
        None => {
            return Err(Error::AmbiguousArchitecture {
                path: path.into(),
                candidates,
            });
        }
    };
    let (_, offset, size) = *chosen;
    let start = usize::try_from(offset).map_err(|_| Error::Corrupt {
        path: path.into(),
        detail: "fat slice offset does not fit in memory".to_string(),
    })?;
    let len = usize::try_from(size).map_err(|_| Error::Corrupt {
        path: path.into(),
        detail: "fat slice size does not fit in memory".to_string(),
    })?;
    let end = start.checked_add(len).ok_or_else(|| Error::Corrupt {
        path: path.into(),
        detail: "fat slice range overflows".to_string(),
    })?;
    let slice = bytes.get(start..end).ok_or_else(|| Error::Corrupt {
        path: path.into(),
        detail: "fat slice range is outside the file".to_string(),
    })?;
    Ok((slice, Some(candidates)))
}

/// Read a separate debug file; a `.dSYM` bundle is searched for the matching UUID.
fn read_debug_file(path: &Path, image: &object::File<'_>, image_path: &Path) -> Result<Vec<u8>> {
    if !path.is_dir() {
        return std::fs::read(path).map_err(|e| Error::io(path, e));
    }
    let dwarf_dir = path.join("Contents").join("Resources").join("DWARF");
    let entries = std::fs::read_dir(&dwarf_dir).map_err(|e| Error::io(&dwarf_dir, e))?;
    let mut candidates: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(&dwarf_dir, e))?;
        let candidate = entry.path();
        if candidate.is_file() {
            candidates.push(candidate);
        }
    }
    candidates.sort();
    if candidates.is_empty() {
        return Err(Error::Corrupt {
            path: path.into(),
            detail: format!("{} contains no DWARF files", dwarf_dir.display()),
        });
    }
    if let Some(uuid) = image.mach_uuid().map_err(|e| Error::Corrupt {
        path: image_path.into(),
        detail: e.to_string(),
    })? {
        let mut matches = Vec::new();
        for candidate in &candidates {
            let bytes = std::fs::read(candidate).map_err(|e| Error::io(candidate, e))?;
            let parsed = object::File::parse(&bytes[..]).map_err(|e| Error::Corrupt {
                path: candidate.clone(),
                detail: e.to_string(),
            })?;
            if parsed.mach_uuid().ok().flatten() == Some(uuid) {
                matches.push(bytes);
            }
        }
        return match matches.len() {
            1 => Ok(matches.pop().expect("one match")),
            0 => Err(Error::DebugFileMismatch {
                image: image_path.into(),
                debug_file: path.into(),
                detail: format!("no DWARF file carries UUID {uuid:02x?}"),
            }),
            _ => Err(Error::DebugFileMismatch {
                image: image_path.into(),
                debug_file: path.into(),
                detail: "several DWARF files carry the same UUID".to_string(),
            }),
        };
    }
    if candidates.len() == 1 {
        return std::fs::read(&candidates[0]).map_err(|e| Error::io(&candidates[0], e));
    }
    Err(Error::DebugFileMismatch {
        image: image_path.into(),
        debug_file: path.into(),
        detail: "several DWARF files and no image UUID to pick one".to_string(),
    })
}

/// Verify that an image and its separate debug file describe the same build.
fn verify_companion(
    image: &object::File<'_>,
    debug: &object::File<'_>,
    image_path: &Path,
    debug_path: &Path,
) -> Result<()> {
    let image_build = image.build_id().map_err(|e| Error::Corrupt {
        path: image_path.into(),
        detail: e.to_string(),
    })?;
    let debug_build = debug.build_id().map_err(|e| Error::Corrupt {
        path: debug_path.into(),
        detail: e.to_string(),
    })?;
    if let (Some(a), Some(b)) = (image_build, debug_build) {
        if a != b {
            return Err(Error::DebugFileMismatch {
                image: image_path.into(),
                debug_file: debug_path.into(),
                detail: format!("build id {a:02x?} does not match {b:02x?}"),
            });
        }
    }
    let image_uuid = image.mach_uuid().map_err(|e| Error::Corrupt {
        path: image_path.into(),
        detail: e.to_string(),
    })?;
    let debug_uuid = debug.mach_uuid().map_err(|e| Error::Corrupt {
        path: debug_path.into(),
        detail: e.to_string(),
    })?;
    if let (Some(a), Some(b)) = (image_uuid, debug_uuid) {
        if a != b {
            return Err(Error::DebugFileMismatch {
                image: image_path.into(),
                debug_file: debug_path.into(),
                detail: format!("Mach-O UUID {a:02x?} does not match {b:02x?}"),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Relocations
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct RelocEntry {
    offset: u64,
    base: u64,
    addend: i64,
    implicit: bool,
    supported: bool,
    kind: String,
}

#[derive(Clone, Debug)]
struct SectionRelocator {
    path: Rc<PathBuf>,
    section: Rc<str>,
    entries: Rc<Vec<RelocEntry>>,
    error: Rc<RefCell<Option<Error>>>,
}

impl SectionRelocator {
    fn empty() -> Self {
        SectionRelocator {
            path: Rc::new(PathBuf::new()),
            section: Rc::from(""),
            entries: Rc::new(Vec::new()),
            error: Rc::new(RefCell::new(None)),
        }
    }

    fn apply(&self, offset: usize, value: u64) -> Option<std::result::Result<u64, Error>> {
        let offset = offset as u64;
        let index = self
            .entries
            .binary_search_by_key(&offset, |entry| entry.offset)
            .ok()?;
        let entry = &self.entries[index];
        if !entry.supported {
            return Some(Err(Error::UnsupportedRelocation {
                path: (*self.path).clone(),
                section: self.section.to_string(),
                offset,
                kind: entry.kind.clone(),
            }));
        }
        let addend = if entry.implicit {
            i128::from(value)
        } else {
            i128::from(entry.addend)
        };
        let total = i128::from(entry.base) + addend;
        match u64::try_from(total) {
            Ok(total) => Some(Ok(total)),
            Err(_) => Some(Err(Error::Overflow {
                location: format!("{} relocation at {offset:#x}", self.section),
                what: "relocated value".to_string(),
            })),
        }
    }
}

impl Relocate<usize> for SectionRelocator {
    fn relocate_address(&self, offset: usize, value: u64) -> gimli::Result<u64> {
        match self.apply(offset, value) {
            Some(Ok(value)) => Ok(value),
            Some(Err(error)) => {
                self.error.borrow_mut().get_or_insert(error);
                Err(gimli::Error::UnsupportedOffset)
            }
            None => Ok(value),
        }
    }

    fn relocate_offset(&self, offset: usize, value: usize) -> gimli::Result<usize> {
        self.relocate_address(offset, value as u64)
            .map(|value| value as usize)
    }
}

struct SectionStore<'a> {
    data: BTreeMap<&'static str, Cow<'a, [u8]>>,
    relocations: BTreeMap<&'static str, SectionRelocator>,
}

fn load_sections<'a>(file: &object::File<'a>, path: &Path) -> Result<SectionStore<'a>> {
    // Supplementary debug information is never loaded implicitly.
    if let Some(section) = file.section_by_name(".gnu_debugaltlink") {
        let data = section.data().map_err(|e| Error::Corrupt {
            path: path.into(),
            detail: e.to_string(),
        })?;
        let companion = data
            .get(20..)
            .and_then(|rest| rest.split(|byte| *byte == 0).next())
            .map(|name| String::from_utf8_lossy(name).into_owned())
            .unwrap_or_else(|| "<unknown altlink target>".to_string());
        return Err(Error::MissingDebugCompanion {
            path: path.into(),
            companion,
        });
    }
    let relocatable = file.kind() == ObjectKind::Relocatable;
    let mut store = SectionStore {
        data: BTreeMap::new(),
        relocations: BTreeMap::new(),
    };
    for id in SECTION_IDS {
        let name = id.name();
        let macho_name = format!("__{}", &name[1..]);
        let section = file
            .section_by_name(name)
            .or_else(|| file.section_by_name(&macho_name));
        let section = match section {
            Some(section) => section,
            None => {
                let legacy = format!(".z{}", &name[1..]);
                if file.section_by_name(&legacy).is_some() {
                    return Err(Error::UnsupportedContainer {
                        path: path.into(),
                        detail: format!(
                            "{legacy} uses legacy zlib compression; recompress it with SHF_COMPRESSED (for example `llvm-objcopy --compress-debug-sections=zlib`)"
                        ),
                    });
                }
                continue;
            }
        };
        let data = section.uncompressed_data().map_err(|e| Error::Corrupt {
            path: path.into(),
            detail: format!("{name}: {e}"),
        })?;
        if relocatable {
            let relocations = build_relocations(file, &section, path, name)?;
            store.relocations.insert(name, relocations);
        }
        store.data.insert(name, data);
    }
    Ok(store)
}

fn build_relocations(
    file: &object::File<'_>,
    section: &object::Section<'_, '_>,
    path: &Path,
    name: &str,
) -> Result<SectionRelocator> {
    let mut entries = Vec::new();
    for (offset, relocation) in section.relocations() {
        let base = match relocation.target() {
            RelocationTarget::Symbol(index) => file
                .symbol_by_index(index)
                .map(|symbol| symbol.address())
                .map_err(|e| Error::Corrupt {
                    path: path.into(),
                    detail: format!("{name} relocation symbol: {e}"),
                })?,
            RelocationTarget::Section(_) => 0,
            _ => 0,
        };
        let supported = matches!(relocation.kind(), RelocationKind::Absolute);
        entries.push(RelocEntry {
            offset,
            base,
            addend: relocation.addend(),
            implicit: relocation.has_implicit_addend(),
            supported,
            kind: format!("{:?} / {:?}", relocation.flags(), relocation.encoding()),
        });
    }
    entries.sort_by_key(|entry| entry.offset);
    Ok(SectionRelocator {
        path: Rc::new(path.into()),
        section: Rc::from(name),
        entries: Rc::new(entries),
        error: Rc::new(RefCell::new(None)),
    })
}

// ---------------------------------------------------------------------------
// DIE index
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Section {
    Info,
    Types,
}

impl Section {
    fn name(self) -> &'static str {
        match self {
            Section::Info => ".debug_info",
            Section::Types => ".debug_types",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DieKey {
    section: Section,
    offset: u64,
}

impl DieKey {
    fn origin(self) -> Origin {
        Origin::Dwarf {
            section: self.section.name().to_string(),
            offset: self.offset,
        }
    }

    fn location(self) -> String {
        format!("{} DIE at {:#x}", self.section.name(), self.offset)
    }
}

#[derive(Clone, Debug)]
struct DieData<'a> {
    key: DieKey,
    tag: DwTag,
    attrs: Vec<(DwAt, AttributeValue<SectionReader<'a>>)>,
    children: Vec<DieKey>,
    parent: Option<DieKey>,
    scope: Option<DieKey>,
    unit: usize,
    base: UnitSectionOffset<usize>,
}

impl<'a> DieData<'a> {
    fn attr(&self, name: DwAt) -> Option<AttributeValue<SectionReader<'a>>> {
        self.attrs
            .iter()
            .find(|(attribute, _)| *attribute == name)
            .map(|(_, value)| value.clone())
    }

    fn flag(&self, name: DwAt) -> bool {
        matches!(self.attr(name), Some(AttributeValue::Flag(true)))
    }
}

fn is_scope_tag(tag: DwTag) -> bool {
    matches!(
        tag,
        constants::DW_TAG_compile_unit
            | constants::DW_TAG_partial_unit
            | constants::DW_TAG_namespace
            | constants::DW_TAG_class_type
            | constants::DW_TAG_structure_type
            | constants::DW_TAG_union_type
            | constants::DW_TAG_enumeration_type
            | constants::DW_TAG_subprogram
            | constants::DW_TAG_inlined_subroutine
            | constants::DW_TAG_lexical_block
    )
}

fn is_named_scope(tag: DwTag) -> bool {
    matches!(
        tag,
        constants::DW_TAG_namespace
            | constants::DW_TAG_class_type
            | constants::DW_TAG_structure_type
            | constants::DW_TAG_union_type
    )
}

fn is_type_tag(tag: DwTag) -> bool {
    matches!(
        tag,
        constants::DW_TAG_base_type
            | constants::DW_TAG_typedef
            | constants::DW_TAG_const_type
            | constants::DW_TAG_volatile_type
            | constants::DW_TAG_restrict_type
            | constants::DW_TAG_atomic_type
            | constants::DW_TAG_pointer_type
            | constants::DW_TAG_reference_type
            | constants::DW_TAG_rvalue_reference_type
            | constants::DW_TAG_ptr_to_member_type
            | constants::DW_TAG_array_type
            | constants::DW_TAG_structure_type
            | constants::DW_TAG_class_type
            | constants::DW_TAG_union_type
            | constants::DW_TAG_enumeration_type
            | constants::DW_TAG_subroutine_type
            | constants::DW_TAG_unspecified_type
            | constants::DW_TAG_interface_type
            | constants::DW_TAG_string_type
            | constants::DW_TAG_set_type
            | constants::DW_TAG_packed_type
            | constants::DW_TAG_shared_type
            | constants::DW_TAG_immutable_type
    )
}

fn die_key(section: Section, base: &UnitSectionOffset<usize>, offset: UnitOffset<usize>) -> DieKey {
    DieKey {
        section,
        offset: (base.0 + offset.0) as u64,
    }
}

/// Section that holds a unit.
fn unit_section<'a>(header: &gimli::UnitHeader<SectionReader<'a>>) -> Section {
    match header.section() {
        SectionId::DebugTypes => Section::Types,
        _ => Section::Info,
    }
}

/// Register the unit unless it is a split unit that needs a companion file.
fn register_unit<'a>(
    dwarf: &DwarfReader<'a>,
    header: gimli::UnitHeader<SectionReader<'a>>,
    path: &Path,
    units: &mut Vec<Unit<SectionReader<'a>>>,
) -> Result<()> {
    let split = !matches!(
        header.type_(),
        UnitType::Compilation | UnitType::Partial | UnitType::Type { .. }
    );
    if split {
        let unit = dwarf.unit(header).map_err(|e| corrupt(path, e))?;
        let companion =
            split_companion_name(dwarf, &unit).unwrap_or_else(|| "<unknown>.dwo".to_string());
        return Err(Error::MissingDebugCompanion {
            path: path.into(),
            companion,
        });
    }
    let unit = dwarf.unit(header).map_err(|e| corrupt(path, e))?;
    units.push(unit);
    Ok(())
}

fn split_companion_name<'a>(
    dwarf: &DwarfReader<'a>,
    unit: &Unit<SectionReader<'a>>,
) -> Option<String> {
    let value = unit.dwo_name().ok().flatten()?;
    let string = dwarf.attr_string(unit, value).ok()?;
    Some(string.to_string_lossy().ok()?.into_owned())
}

struct Collector<'a> {
    path: PathBuf,
    index: BTreeMap<DieKey, DieData<'a>>,
    specified_by: BTreeMap<DieKey, Vec<DieKey>>,
    signatures: BTreeMap<u64, DieKey>,
}

impl<'a> Collector<'a> {
    fn walk(
        &mut self,
        node: EntriesTreeNode<'_, '_, SectionReader<'a>>,
        parent: Option<DieKey>,
        scope: Option<DieKey>,
        depth: usize,
        unit_index: usize,
        section: Section,
        base: &UnitSectionOffset<usize>,
    ) -> Result<()> {
        if depth > MAX_DIE_DEPTH {
            return Err(Error::Corrupt {
                path: self.path.clone(),
                detail: format!("DIE nesting exceeds {MAX_DIE_DEPTH} levels"),
            });
        }
        let entry = node.entry();
        let key = die_key(section, base, entry.offset());
        let attrs: Vec<(DwAt, AttributeValue<SectionReader<'a>>)> = entry
            .attrs()
            .iter()
            .map(|attribute| (attribute.name(), attribute.value()))
            .collect();
        let tag = entry.tag();
        for attribute in [
            constants::DW_AT_specification,
            constants::DW_AT_abstract_origin,
        ] {
            let value = attrs
                .iter()
                .find(|(name, _)| *name == attribute)
                .map(|(_, value)| value.clone());
            if let Some(value) = value {
                if let Some(target) = reference_key(section, base, &value) {
                    self.specified_by.entry(target).or_default().push(key);
                }
            }
        }
        let child_scope = if is_scope_tag(tag) { Some(key) } else { scope };
        self.index.insert(
            key,
            DieData {
                key,
                tag,
                attrs,
                children: Vec::new(),
                parent,
                scope,
                unit: unit_index,
                base: *base,
            },
        );
        let mut children = Vec::new();
        let mut iter = node.children();
        while let Some(child) = iter.next().map_err(|e| corrupt(&self.path, e))? {
            let child_key = die_key(section, base, child.entry().offset());
            children.push(child_key);
            self.walk(
                child,
                Some(key),
                child_scope,
                depth + 1,
                unit_index,
                section,
                base,
            )?;
        }
        if let Some(data) = self.index.get_mut(&key) {
            data.children = children;
        }
        Ok(())
    }
}

/// Interpret a reference-form attribute value as an absolute DIE key.
fn reference_key(
    section: Section,
    base: &UnitSectionOffset<usize>,
    value: &AttributeValue<SectionReader<'_>>,
) -> Option<DieKey> {
    match value {
        AttributeValue::UnitRef(offset) => Some(die_key(section, base, *offset)),
        AttributeValue::DebugInfoRef(offset) => Some(DieKey {
            section: Section::Info,
            offset: offset.0 as u64,
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Frontend
// ---------------------------------------------------------------------------

struct Frontend<'a> {
    path: PathBuf,
    dwarf: DwarfReader<'a>,
    units: Vec<Unit<SectionReader<'a>>>,
    index: BTreeMap<DieKey, DieData<'a>>,
    graph: TypeGraph,
    cache: BTreeMap<DieKey, TypeId>,
    definitions: BTreeMap<(Option<DieKey>, String), Vec<DieKey>>,
    specified_by: BTreeMap<DieKey, Vec<DieKey>>,
    signatures: BTreeMap<u64, DieKey>,
    /// Compilation-unit name of every unit, used as the name domain of its types.
    unit_domains: Vec<Option<String>>,
    symbols: BTreeMap<String, GlobalSymbol>,
    functions: BTreeMap<String, GlobalFunction>,
}

impl<'a> Frontend<'a> {
    // -- pass 1: collect every DIE -----------------------------------------

    fn collect_all(&mut self) -> Result<()> {
        let mut collector = Collector {
            path: self.path.clone(),
            index: BTreeMap::new(),
            specified_by: BTreeMap::new(),
            signatures: BTreeMap::new(),
        };
        for unit_index in 0..self.units.len() {
            let unit = &self.units[unit_index];
            let header = unit.header.clone();
            let _ = &header;
            let base = unit.header.offset();
            let section = unit_section(&unit.header);
            let mut tree = unit
                .entries_tree(None)
                .map_err(|e| corrupt(&self.path, e))?;
            let root = tree.root().map_err(|e| corrupt(&self.path, e))?;
            collector.walk(root, None, None, 0, unit_index, section, &base)?;
            if let UnitType::Type {
                type_signature,
                type_offset,
            }
            | UnitType::SplitType {
                type_signature,
                type_offset,
            } = unit.header.type_()
            {
                let key = die_key(section, &base, type_offset);
                collector.signatures.insert(type_signature.0, key);
            }
        }
        self.index = collector.index;
        self.specified_by = collector.specified_by;
        self.signatures = collector.signatures;
        self.unit_domains = (0..self.units.len())
            .map(|unit_index| {
                let unit = &self.units[unit_index];
                let key = die_key(
                    unit_section(&unit.header),
                    &unit.header.offset(),
                    unit.root_offset(),
                );
                self.die_string(self.index.get(&key)?, constants::DW_AT_name)
            })
            .map(|name| name.and_then(|name| source_basename(&name)))
            .collect();
        Ok(())
    }

    /// Compilation unit a record was defined in, as a path-free label.
    fn unit_domain(&self, unit: usize) -> Option<String> {
        self.unit_domains.get(unit).cloned().flatten()
    }

    // -- pass 2: resolve types ---------------------------------------------

    fn resolve_all(&mut self) -> Result<()> {
        self.prepare_definitions();
        let keys: Vec<DieKey> = self
            .index
            .iter()
            .filter(|(_, die)| is_type_tag(die.tag))
            .map(|(key, _)| *key)
            .collect();
        for key in keys {
            self.type_for(key)?;
        }
        Ok(())
    }

    /// Index complete type definitions by scope and qualified name, for forward
    /// declarations that carry no explicit `DW_AT_specification` link.
    fn prepare_definitions(&mut self) {
        let mut groups: Vec<((Option<DieKey>, String), DieKey)> = Vec::new();
        for (key, die) in &self.index {
            if !matches!(
                die.tag,
                constants::DW_TAG_structure_type
                    | constants::DW_TAG_class_type
                    | constants::DW_TAG_union_type
                    | constants::DW_TAG_enumeration_type
                    | constants::DW_TAG_typedef
            ) {
                continue;
            }
            if die.flag(constants::DW_AT_declaration) {
                continue;
            }
            let Some(name) = self.raw_name(*key, die) else {
                continue;
            };
            groups.push(((die.scope, name), *key));
        }
        for (group, key) in groups {
            self.definitions.entry(group).or_default().push(key);
        }
    }

    fn type_for(&mut self, key: DieKey) -> Result<TypeId> {
        if let Some(id) = self.cache.get(&key) {
            return Ok(*id);
        }
        let die = match self.index.get(&key) {
            Some(die) => die.clone(),
            None => {
                return Err(Error::Corrupt {
                    path: self.path.clone(),
                    detail: format!("{} is referenced but missing", key.location()),
                });
            }
        };
        let id = match die.tag {
            constants::DW_TAG_base_type => self.base_type(key, &die)?,
            constants::DW_TAG_typedef => self.typedef_type(key, &die)?,
            constants::DW_TAG_const_type => self.qualified_type(key, &die, Qualifier::Const)?,
            constants::DW_TAG_volatile_type => {
                self.qualified_type(key, &die, Qualifier::Volatile)?
            }
            constants::DW_TAG_restrict_type => {
                self.qualified_type(key, &die, Qualifier::Restrict)?
            }
            constants::DW_TAG_atomic_type => self.qualified_type(key, &die, Qualifier::Volatile)?,
            constants::DW_TAG_pointer_type => self.pointer_type(key, &die, None)?,
            constants::DW_TAG_reference_type => {
                self.pointer_type(key, &die, Some(ReferenceKind::Lvalue))?
            }
            constants::DW_TAG_rvalue_reference_type => {
                self.pointer_type(key, &die, Some(ReferenceKind::Rvalue))?
            }
            constants::DW_TAG_ptr_to_member_type => self.opaque_type(
                key,
                &die,
                "pointer-to-member type has no static ISF equivalent",
            )?,
            constants::DW_TAG_array_type => self.array_type(key, &die)?,
            constants::DW_TAG_structure_type
            | constants::DW_TAG_class_type
            | constants::DW_TAG_union_type => self.composite_type(key, &die)?,
            constants::DW_TAG_enumeration_type => self.enum_type(key, &die)?,
            constants::DW_TAG_subroutine_type => {
                let signature = self.signature(key, &die)?;
                let id = self.graph.push(Node::Function(signature));
                self.cache.insert(key, id);
                id
            }
            constants::DW_TAG_unspecified_type => {
                // `decltype(nullptr)` and unspecified return types carry no layout.
                let id = self.graph.void();
                self.cache.insert(key, id);
                id
            }
            other => self.opaque_type(
                key,
                &die,
                &format!("DWARF type tag {other:?} has no static ISF equivalent"),
            )?,
        };
        self.cache.insert(key, id);
        Ok(id)
    }

    fn base_type(&mut self, key: DieKey, die: &DieData<'a>) -> Result<TypeId> {
        let name = self.raw_name(key, die).unwrap_or_default();
        let encoding = die.attr(constants::DW_AT_encoding);
        let (kind, signed, reason) = match encoding {
            Some(AttributeValue::Encoding(constants::DW_ATE_boolean)) => {
                (BaseKind::Bool, false, None)
            }
            Some(AttributeValue::Encoding(constants::DW_ATE_float))
            | Some(AttributeValue::Encoding(constants::DW_ATE_complex_float))
            | Some(AttributeValue::Encoding(constants::DW_ATE_imaginary_float))
            | Some(AttributeValue::Encoding(constants::DW_ATE_decimal_float)) => {
                (BaseKind::Float, true, None)
            }
            Some(AttributeValue::Encoding(constants::DW_ATE_signed))
            | Some(AttributeValue::Encoding(constants::DW_ATE_signed_char))
            | Some(AttributeValue::Encoding(constants::DW_ATE_signed_fixed)) => {
                (BaseKind::Int, true, None)
            }
            Some(AttributeValue::Encoding(constants::DW_ATE_unsigned))
            | Some(AttributeValue::Encoding(constants::DW_ATE_unsigned_char))
            | Some(AttributeValue::Encoding(constants::DW_ATE_unsigned_fixed)) => {
                (BaseKind::Int, false, None)
            }
            Some(AttributeValue::Encoding(constants::DW_ATE_UTF))
            | Some(AttributeValue::Encoding(constants::DW_ATE_UCS))
            | Some(AttributeValue::Encoding(constants::DW_ATE_ASCII)) => {
                (BaseKind::Char, false, None)
            }
            Some(AttributeValue::Encoding(constants::DW_ATE_address)) => {
                (BaseKind::Pointer, false, None)
            }
            Some(AttributeValue::Encoding(other)) => (
                BaseKind::Opaque,
                false,
                Some(format!("DW_AT_encoding {other:?} is not supported")),
            ),
            _ => (BaseKind::Int, false, None),
        };
        let mut size = self.byte_size_attr(key, die)?.unwrap_or(0);
        if size == 0 && kind == BaseKind::Pointer {
            size = self.graph.target().pointer_size;
        }
        if kind != BaseKind::Void && size == 0 {
            return Err(Error::UnsupportedLayout {
                location: key.location(),
                detail: "base type record has no DW_AT_byte_size".to_string(),
            });
        }
        let alignment = match self.const_attribute(key, die, constants::DW_AT_alignment) {
            Ok(Some(value)) => Some(u64::try_from(value).map_err(|_| Error::Overflow {
                location: key.location(),
                what: "alignment".to_string(),
            })?),
            _ => None,
        };
        Ok(self.graph.base(BaseRecord {
            name: BaseName::Source(name),
            size,
            signed,
            kind,
            alignment,
            unsupported_reason: reason,
            origin: key.origin(),
        }))
    }

    fn typedef_type(&mut self, key: DieKey, die: &DieData<'a>) -> Result<TypeId> {
        let name = self.raw_name(key, die).ok_or_else(|| Error::Corrupt {
            path: self.path.clone(),
            detail: format!("typedef {} has no name", key.location()),
        })?;
        let slot = self.graph.typedef_slot(name, key.origin());
        let domain = self.unit_domain(die.unit);
        self.graph.set_domain(slot, domain)?;
        self.cache.insert(key, slot);
        let target = match self.type_reference(key, die)? {
            Some(target) => target,
            None => self.graph.void(),
        };
        self.graph.set_typedef_target(slot, target)?;
        Ok(slot)
    }

    fn qualified_type(
        &mut self,
        key: DieKey,
        die: &DieData<'a>,
        qualifier: Qualifier,
    ) -> Result<TypeId> {
        let target = match self.type_reference(key, die)? {
            Some(target) => target,
            None => self.graph.void(),
        };
        Ok(self.graph.qualified(target, qualifier))
    }

    fn pointer_type(
        &mut self,
        key: DieKey,
        die: &DieData<'a>,
        reference: Option<ReferenceKind>,
    ) -> Result<TypeId> {
        let target = match self.type_reference(key, die)? {
            Some(target) => target,
            None => self.graph.void(),
        };
        let size = self.byte_size_attr(key, die)?;
        match reference {
            Some(kind) => Ok(self.graph.reference_to(target, kind)),
            None => Ok(self.graph.pointer_to(target, size)),
        }
    }

    fn array_type(&mut self, key: DieKey, die: &DieData<'a>) -> Result<TypeId> {
        let element = self
            .type_reference(key, die)?
            .ok_or_else(|| Error::UnsupportedLayout {
                location: key.location(),
                detail: "array type has no element type".to_string(),
            })?;
        let mut counts = Vec::new();
        for child in &die.children {
            let subrange = match self.index.get(child) {
                Some(subrange) => subrange.clone(),
                None => continue,
            };
            if subrange.tag != constants::DW_TAG_subrange_type {
                continue;
            }
            counts.push(self.subrange_count(*child, &subrange)?);
        }
        // The first subrange is the outermost dimension.
        let mut current = element;
        for count in counts.into_iter().rev() {
            current = self.graph.array_of(current, count);
        }
        Ok(current)
    }

    fn subrange_count(&self, key: DieKey, die: &DieData<'a>) -> Result<u64> {
        if let Some(count) = self.const_attribute(key, die, constants::DW_AT_count)? {
            return u64::try_from(count).map_err(|_| Error::UnsupportedLayout {
                location: key.location(),
                detail: "negative array count".to_string(),
            });
        }
        let lower = self
            .const_attribute(key, die, constants::DW_AT_lower_bound)?
            .unwrap_or(0);
        match self.const_attribute(key, die, constants::DW_AT_upper_bound)? {
            Some(upper) if upper >= lower => {
                let count = upper - lower + 1;
                u64::try_from(count).map_err(|_| Error::Overflow {
                    location: key.location(),
                    what: "array count".to_string(),
                })
            }
            // A missing or negative upper bound is a flexible trailing array.
            _ => Ok(0),
        }
    }

    fn composite_type(&mut self, key: DieKey, die: &DieData<'a>) -> Result<TypeId> {
        let kind = if die.tag == constants::DW_TAG_union_type {
            CompositeKind::Union
        } else {
            CompositeKind::Struct
        };
        let name = self.qualified_name(key);
        let declaration = die.flag(constants::DW_AT_declaration);
        if declaration {
            let reason = match self.definition_for(key) {
                Link::Single(definition) => {
                    let id = self.type_for(definition)?;
                    self.cache.insert(key, id);
                    return Ok(id);
                }
                Link::Missing => None,
                Link::Ambiguous(reason) => Some(reason),
            };
            let id = self.graph.composite_slot();
            let domain = self.unit_domain(die.unit);
            if let Ok(record) = self.graph.composite_mut(id) {
                record.name = name;
                record.kind = kind;
                record.domain = domain;
                record.origin = key.origin();
                record.incomplete = true;
                record.unsupported = reason;
            }
            self.cache.insert(key, id);
            return Ok(id);
        }

        let size = self.byte_size_attr(key, die)?;
        let alignment = match self.const_attribute(key, die, constants::DW_AT_alignment) {
            Ok(Some(value)) => Some(u64::try_from(value).map_err(|_| Error::Overflow {
                location: key.location(),
                what: "alignment".to_string(),
            })?),
            _ => None,
        };
        // Register the aggregate before its members resolve, so recursion works.
        let id = self.graph.composite_slot();
        self.cache.insert(key, id);
        let mut members = Vec::new();
        let mut unsupported: Option<String> = None;
        let mut base_index = 0usize;
        for child in &die.children {
            let Some(record) = self.index.get(child).cloned() else {
                continue;
            };
            if unsupported.is_some() {
                continue;
            }
            let outcome = match record.tag {
                constants::DW_TAG_member => self.member(*child, &record)?,
                constants::DW_TAG_inheritance => {
                    let virtual_base = matches!(
                        record.attr(constants::DW_AT_virtuality),
                        Some(AttributeValue::Virtuality(constants::DW_VIRTUALITY_virtual))
                    );
                    if virtual_base {
                        MemberOutcome::Unsupported(
                            "virtual base classes have no static ISF equivalent".to_string(),
                        )
                    } else {
                        base_index += 1;
                        let name = format!("__base_{base_index}");
                        match self.member(*child, &record)? {
                            MemberOutcome::Member(Some(member)) => {
                                MemberOutcome::Member(Some(Member {
                                    name: Some(name),
                                    anonymous: false,
                                    ..member
                                }))
                            }
                            other => other,
                        }
                    }
                }
                constants::DW_TAG_variant_part | constants::DW_TAG_variant => {
                    MemberOutcome::Unsupported(
                        "variant parts (Rust enums, C++ discriminated unions) have no static ISF equivalent"
                            .to_string(),
                    )
                }
                _ => continue,
            };
            match outcome {
                MemberOutcome::Member(Some(member)) => members.push(member),
                MemberOutcome::Member(None) => {}
                MemberOutcome::Unsupported(reason) => {
                    unsupported = Some(reason);
                }
            }
        }
        let domain = self.unit_domain(die.unit);
        if let Ok(record) = self.graph.composite_mut(id) {
            record.name = name;
            record.kind = kind;
            record.size = size;
            record.alignment = alignment;
            record.members = members;
            record.domain = domain;
            record.origin = key.origin();
            record.incomplete = false;
            record.unsupported = unsupported;
        }
        Ok(id)
    }

    fn member(&mut self, key: DieKey, die: &DieData<'a>) -> Result<MemberOutcome> {
        let name = self.raw_name(key, die).filter(|name| !name.is_empty());
        let location = match self.const_attribute(key, die, constants::DW_AT_data_member_location) {
            Ok(location) => location,
            Err(Error::UnsupportedLayout { detail, .. }) => {
                return Ok(MemberOutcome::Unsupported(format!(
                    "runtime member location: {detail}"
                )));
            }
            Err(error) => return Err(error),
        };
        let bit_size = match self.const_attribute(key, die, constants::DW_AT_bit_size) {
            Ok(size) => size,
            Err(Error::UnsupportedLayout { detail, .. }) => {
                return Ok(MemberOutcome::Unsupported(format!(
                    "runtime bit-field size: {detail}"
                )));
            }
            Err(error) => return Err(error),
        };
        let declared = self.type_reference(key, die)?;
        match bit_size {
            Some(bit_size) => {
                let length = u64::try_from(bit_size).map_err(|_| Error::Overflow {
                    location: key.location(),
                    what: "bit-field width".to_string(),
                })?;
                if length == 0 {
                    // Zero-width bit-fields only separate following members.
                    return Ok(MemberOutcome::Member(None));
                }
                let Some(declared) = declared else {
                    return Ok(MemberOutcome::Unsupported(
                        "bit-field without DW_AT_type".to_string(),
                    ));
                };
                let signed = self.graph.base_signed(declared).unwrap_or(false);
                let bit_start =
                    match self.const_attribute(key, die, constants::DW_AT_data_bit_offset) {
                        Ok(Some(offset)) => {
                            u64::try_from(offset).map_err(|_| Error::UnsupportedLayout {
                                location: key.location(),
                                detail: "negative DW_AT_data_bit_offset".to_string(),
                            })?
                        }
                        Ok(None) => {
                            let old =
                                self.const_attribute(key, die, constants::DW_AT_bit_offset)?;
                            let Some(old) = old else {
                                return Ok(MemberOutcome::Unsupported(
                                    "bit-field without DW_AT_data_bit_offset or DW_AT_bit_offset"
                                        .to_string(),
                                ));
                            };
                            let old = u64::try_from(old).map_err(|_| Error::UnsupportedLayout {
                                location: key.location(),
                                detail: "negative DW_AT_bit_offset".to_string(),
                            })?;
                            let data_offset = location.unwrap_or(0);
                            let data_offset = u64::try_from(data_offset).map_err(|_| {
                                Error::UnsupportedLayout {
                                    location: key.location(),
                                    detail: "negative member offset".to_string(),
                                }
                            })?;
                            let storage = self.member_storage_bytes(key, die, declared)?;
                            self.endian().checked_bit_field_start(
                                key,
                                data_offset,
                                storage,
                                old,
                                length,
                            )?
                        }
                        Err(Error::UnsupportedLayout { detail, .. }) => {
                            return Ok(MemberOutcome::Unsupported(format!(
                                "runtime bit-field offset: {detail}"
                            )));
                        }
                        Err(error) => return Err(error),
                    };
                let member = self.graph.bitfield_member(
                    name,
                    &key.origin(),
                    bit_start,
                    length,
                    declared,
                    signed,
                )?;
                Ok(MemberOutcome::Member(Some(member)))
            }
            None => {
                let declared = match declared {
                    Some(declared) => declared,
                    None => {
                        // A member without a type is only representable when the
                        // record itself states its size.
                        return match self.byte_size_attr(key, die)? {
                            Some(size) => Ok(MemberOutcome::Unsupported(format!(
                                "anonymous member without DW_AT_type of {size} bytes"
                            ))),
                            None => Ok(MemberOutcome::Unsupported(
                                "member without DW_AT_type".to_string(),
                            )),
                        };
                    }
                };
                let offset = match location {
                    Some(offset) => {
                        u64::try_from(offset).map_err(|_| Error::UnsupportedLayout {
                            location: key.location(),
                            detail: "negative member offset".to_string(),
                        })?
                    }
                    None => 0,
                };
                Ok(MemberOutcome::Member(Some(Member {
                    name: name.clone(),
                    offset,
                    ty: declared,
                    bitfield: None,
                    anonymous: name.is_none(),
                })))
            }
        }
    }

    fn member_storage_bytes(
        &self,
        key: DieKey,
        die: &DieData<'a>,
        declared: TypeId,
    ) -> Result<u64> {
        if let Some(size) = self.byte_size_attr(key, die)? {
            return Ok(size);
        }
        let _ = declared;
        if let Some(type_key) = self.type_key(key, die)? {
            if let Some(size) = self.die_byte_size(type_key, 0)? {
                return Ok(size);
            }
        }
        Err(Error::UnsupportedLayout {
            location: key.location(),
            detail: "bit-field storage width is unknown".to_string(),
        })
    }

    fn die_byte_size(&self, key: DieKey, depth: usize) -> Result<Option<u64>> {
        if depth > MAX_DIE_DEPTH {
            return Ok(None);
        }
        let Some(die) = self.index.get(&key) else {
            return Ok(None);
        };
        if let Some(size) = self.byte_size_attr(key, die)? {
            return Ok(Some(size));
        }
        if let Some(target) = self.type_key(key, die)? {
            return self.die_byte_size(target, depth + 1);
        }
        Ok(None)
    }

    fn enum_type(&mut self, key: DieKey, die: &DieData<'a>) -> Result<TypeId> {
        let name = self.qualified_name(key);
        let size = self
            .byte_size_attr(key, die)?
            .ok_or_else(|| Error::UnsupportedLayout {
                location: key.location(),
                detail: "enumeration has no DW_AT_byte_size".to_string(),
            })?;
        let base = self.type_reference(key, die)?;
        let mut constants = Vec::new();
        for child in &die.children {
            let Some(record) = self.index.get(child).cloned() else {
                continue;
            };
            if record.tag != constants::DW_TAG_enumerator {
                continue;
            }
            let constant_name = self.raw_name(*child, &record).unwrap_or_default();
            let value = self
                .const_attribute(*child, &record, constants::DW_AT_const_value)?
                .ok_or_else(|| Error::UnsupportedLayout {
                    location: child.location(),
                    detail: "enumerator has no constant value".to_string(),
                })?;
            constants.push((constant_name, int_value(value)?));
        }
        let record = EnumRecord {
            name,
            size,
            base,
            constants,
            domain: self.unit_domain(die.unit),
            origin: key.origin(),
            unsupported: None,
        };
        let id = self.graph.push(Node::Enum(record));
        self.cache.insert(key, id);
        Ok(id)
    }

    fn opaque_type(&mut self, key: DieKey, die: &DieData<'a>, reason: &str) -> Result<TypeId> {
        let size = self.byte_size_attr(key, die)?;
        let Some(size) = size else {
            return Err(Error::UnsupportedLayout {
                location: key.location(),
                detail: format!("{reason}, and the record has no DW_AT_byte_size"),
            });
        };
        let name = self
            .qualified_name(key)
            .or_else(|| self.raw_name(key, die))
            .unwrap_or_default();
        let id = self.graph.base(BaseRecord {
            name: BaseName::Source(name),
            size,
            signed: false,
            kind: BaseKind::Opaque,
            alignment: None,
            unsupported_reason: Some(reason.to_string()),
            origin: key.origin(),
        });
        self.cache.insert(key, id);
        Ok(id)
    }

    fn signature(&mut self, key: DieKey, die: &DieData<'a>) -> Result<FunctionRecord> {
        // GCC records the signature in a `DW_TAG_subroutine_type` child; clang
        // puts the return type and the parameters on the subprogram itself.
        let mut carrier_key = key;
        let mut carrier = die.clone();
        if let Some(type_key) = self.type_key(key, die)? {
            if let Some(record) = self.index.get(&type_key).cloned() {
                if record.tag == constants::DW_TAG_subroutine_type {
                    carrier_key = type_key;
                    carrier = record;
                }
            }
        }
        let return_type = match self.type_reference(carrier_key, &carrier)? {
            Some(return_type) => return_type,
            None => self.graph.void(),
        };
        let mut parameters = Vec::new();
        let mut variadic = false;
        for child in &carrier.children {
            let Some(record) = self.index.get(child).cloned() else {
                continue;
            };
            match record.tag {
                constants::DW_TAG_formal_parameter => {
                    let name = self.raw_name(*child, &record).filter(|n| !n.is_empty());
                    let ty = match self.type_reference(*child, &record)? {
                        Some(ty) => ty,
                        None => self.graph.void(),
                    };
                    parameters.push((name, ty));
                }
                constants::DW_TAG_unspecified_parameters => variadic = true,
                _ => {}
            }
        }
        let calling_convention = calling_convention(die).or_else(|| calling_convention(&carrier));
        Ok(FunctionRecord {
            return_type,
            parameters,
            variadic,
            calling_convention,
        })
    }

    /// Resolve `DW_AT_type` of a record.
    fn type_reference(&mut self, key: DieKey, die: &DieData<'a>) -> Result<Option<TypeId>> {
        match self.type_key(key, die)? {
            Some(target) => Ok(Some(self.type_for(target)?)),
            None => Ok(None),
        }
    }

    fn type_key(&self, key: DieKey, die: &DieData<'a>) -> Result<Option<DieKey>> {
        let _ = key;
        match die.attr(constants::DW_AT_type) {
            None => Ok(None),
            Some(value) => self
                .reference_target(die, value)
                .map(Some)
                .map_err(|error| error),
        }
    }

    fn reference_target(
        &self,
        die: &DieData<'a>,
        value: AttributeValue<SectionReader<'a>>,
    ) -> Result<DieKey> {
        if let Some(key) = reference_key(die.key.section, &die.base, &value) {
            return Ok(key);
        }
        match value {
            AttributeValue::DebugTypesRef(signature) => self
                .signatures
                .get(&signature.0)
                .copied()
                .ok_or_else(|| Error::Corrupt {
                    path: self.path.clone(),
                    detail: format!(
                        "type signature {:#x} is not defined in .debug_types",
                        signature.0
                    ),
                }),
            AttributeValue::DebugInfoRefSup(_) | AttributeValue::DebugStrRefSup(_) => {
                Err(Error::MissingDebugCompanion {
                    path: self.path.clone(),
                    companion: "<supplementary object>".to_string(),
                })
            }
            other => Err(Error::Corrupt {
                path: self.path.clone(),
                detail: format!(
                    "{} uses reference form {other:?} that cannot be resolved",
                    die.key.location()
                ),
            }),
        }
    }

    /// Link a declaration to its definition, or explain why that is not possible.
    fn definition_for(&mut self, declaration: DieKey) -> Link {
        if let Some(candidates) = self.specified_by.get(&declaration) {
            let definitions: Vec<DieKey> = candidates
                .iter()
                .copied()
                .filter(|key| {
                    self.index
                        .get(key)
                        .is_some_and(|die| !die.flag(constants::DW_AT_declaration))
                })
                .collect();
            match definitions.len() {
                0 => {}
                1 => return Link::Single(definitions[0]),
                _ => {
                    return Link::Ambiguous(format!(
                        "several definitions name this declaration: {}",
                        definitions
                            .iter()
                            .map(|key| key.location())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
        }
        let Some(die) = self.index.get(&declaration).cloned() else {
            return Link::Missing;
        };
        let Some(name) = self.raw_name(declaration, &die) else {
            return Link::Missing;
        };
        match self.definitions.get(&(die.scope, name)) {
            None => Link::Missing,
            Some(candidates) => match candidates.len() {
                0 => Link::Missing,
                1 => Link::Single(candidates[0]),
                _ => Link::Ambiguous(format!(
                    "{} definitions share this qualified name: {}",
                    candidates.len(),
                    candidates
                        .iter()
                        .map(|key| key.location())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            },
        }
    }

    // -- attributes -------------------------------------------------------

    fn raw_name(&self, _key: DieKey, die: &DieData<'a>) -> Option<String> {
        self.die_string(die, constants::DW_AT_name)
            .or_else(|| self.die_string(die, constants::DW_AT_linkage_name))
    }

    fn qualified_name(&self, key: DieKey) -> Option<String> {
        let mut parts = Vec::new();
        let mut current = self.index.get(&key)?.scope;
        let mut guard = 0usize;
        while let Some(scope) = current {
            guard += 1;
            if guard > MAX_DIE_DEPTH {
                break;
            }
            let die = self.index.get(&scope)?;
            if is_named_scope(die.tag) {
                if let Some(name) = self.die_string(die, constants::DW_AT_name) {
                    if !name.is_empty() {
                        parts.push(name);
                    }
                }
            }
            current = die.scope;
        }
        parts.reverse();
        let own = self.index.get(&key)?;
        let name = self.die_string(own, constants::DW_AT_name)?;
        parts.push(name);
        Some(parts.join("::"))
    }

    fn die_string(&self, die: &DieData<'a>, name: DwAt) -> Option<String> {
        let value = die.attr(name)?;
        self.string_value(die.unit, value)
    }

    fn string_value(
        &self,
        unit_index: usize,
        value: AttributeValue<SectionReader<'a>>,
    ) -> Option<String> {
        match value {
            AttributeValue::String(bytes) => Some(bytes.to_string_lossy().ok()?.into_owned()),
            AttributeValue::DebugStrRef(_)
            | AttributeValue::DebugStrOffsetsIndex(_)
            | AttributeValue::DebugLineStrRef(_) => {
                let unit = self.units.get(unit_index)?;
                let slice = self.dwarf.attr_string(unit, value).ok()?;
                Some(slice.to_string_lossy().ok()?.into_owned())
            }
            _ => None,
        }
    }

    fn byte_size_attr(&self, key: DieKey, die: &DieData<'a>) -> Result<Option<u64>> {
        match self.const_attribute(key, die, constants::DW_AT_byte_size)? {
            Some(value) => {
                let value = u64::try_from(value).map_err(|_| Error::UnsupportedLayout {
                    location: key.location(),
                    detail: "negative DW_AT_byte_size".to_string(),
                })?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    fn const_attribute(&self, key: DieKey, die: &DieData<'a>, name: DwAt) -> Result<Option<i128>> {
        match die.attr(name) {
            None => Ok(None),
            Some(value) => {
                self.evaluate(die, value)
                    .map(Some)
                    .map_err(|detail| Error::UnsupportedLayout {
                        location: key.location(),
                        detail,
                    })
            }
        }
    }

    /// Evaluate a constant form or a constant-only DWARF expression.
    fn evaluate(
        &self,
        die: &DieData<'a>,
        value: AttributeValue<SectionReader<'a>>,
    ) -> std::result::Result<i128, String> {
        match value {
            AttributeValue::Udata(value) => Ok(i128::from(value)),
            AttributeValue::Sdata(value) => Ok(i128::from(value)),
            AttributeValue::Data1(value) => Ok(i128::from(value)),
            AttributeValue::Data2(value) => Ok(i128::from(value)),
            AttributeValue::Data4(value) => Ok(i128::from(value)),
            AttributeValue::Data8(value) => Ok(i128::from(value)),
            AttributeValue::Exprloc(expression) => self.evaluate_expression(die, expression),
            other => Err(format!("attribute is not a constant form: {other:?}")),
        }
    }

    fn evaluate_expression(
        &self,
        die: &DieData<'a>,
        expression: Expression<SectionReader<'a>>,
    ) -> std::result::Result<i128, String> {
        let unit = self
            .units
            .get(die.unit)
            .ok_or_else(|| "unit is not loaded".to_string())?;
        let mut stack: Vec<i128> = Vec::new();
        let mut operations = expression.operations(unit.encoding());
        while let Some(operation) = operations
            .next()
            .map_err(|error| format!("DWARF expression: {error}"))?
        {
            match operation {
                Operation::UnsignedConstant { value } => stack.push(i128::from(value)),
                Operation::SignedConstant { value } => stack.push(i128::from(value)),
                Operation::PlusConstant { value } => {
                    // DWARF 2/3 store a plain `DW_OP_plus_uconst` as the member
                    // location; the implicit base value is zero here.
                    let top = stack.pop().unwrap_or(0);
                    stack.push(top + i128::from(value));
                }
                Operation::Address { address } => stack.push(i128::from(address)),
                Operation::AddressIndex { index } | Operation::ConstantIndex { index } => {
                    let address = self
                        .dwarf
                        .address(unit, index)
                        .map_err(|error| format!("DW_AT_addr index: {error}"))?;
                    stack.push(i128::from(address));
                }
                Operation::Pick { index } => {
                    let index = usize::from(index);
                    if index >= stack.len() {
                        return Err("DW_OP_pick outside the stack".to_string());
                    }
                    let value = stack[stack.len() - 1 - index];
                    stack.push(value);
                }
                Operation::Swap => {
                    if stack.len() < 2 {
                        return Err("DW_OP_swap on a short stack".to_string());
                    }
                    let len = stack.len();
                    stack.swap(len - 1, len - 2);
                }
                Operation::Drop => {
                    stack.pop().ok_or_else(|| "empty stack".to_string())?;
                }
                Operation::Nop => {}
                binary @ (Operation::Plus
                | Operation::Minus
                | Operation::Mul
                | Operation::Div
                | Operation::Mod
                | Operation::And
                | Operation::Or
                | Operation::Xor
                | Operation::Shl
                | Operation::Shr) => {
                    // Missing operands are the implicit base value of a member
                    // location expression, which is zero for a static offset.
                    while stack.len() < 2 {
                        stack.insert(0, 0);
                    }
                    let right = stack.pop().ok_or_else(|| "empty stack".to_string())?;
                    let left = stack.pop().ok_or_else(|| "empty stack".to_string())?;
                    let value = match binary {
                        Operation::Plus => left + right,
                        Operation::Minus => left - right,
                        Operation::Mul => left * right,
                        Operation::Div => {
                            if right == 0 {
                                return Err("division by zero".to_string());
                            }
                            left / right
                        }
                        Operation::Mod => {
                            if right == 0 {
                                return Err("modulo by zero".to_string());
                            }
                            left % right
                        }
                        Operation::And => left & right,
                        Operation::Or => left | right,
                        Operation::Xor => left ^ right,
                        Operation::Shl => left << right,
                        Operation::Shr => left >> right,
                        other => return Err(format!("unsupported operation {other:?}")),
                    };
                    stack.push(value);
                }
                Operation::Neg => {
                    let top = stack.pop().unwrap_or(0);
                    stack.push(-top);
                }
                Operation::Abs => {
                    let top = stack.pop().ok_or_else(|| "empty stack".to_string())?;
                    stack.push(top.abs());
                }
                Operation::Not => {
                    let top = stack.pop().ok_or_else(|| "empty stack".to_string())?;
                    stack.push(!top);
                }
                other => {
                    return Err(format!(
                        "operation {other:?} needs target state and cannot be folded"
                    ));
                }
            }
        }
        stack
            .pop()
            .ok_or_else(|| "expression leaves no value".to_string())
    }

    fn endian(&self) -> BigEndianBitField {
        BigEndianBitField {
            endian: self.graph.target().endian,
        }
    }

    // -- globals ----------------------------------------------------------

    fn collect_globals(&mut self) -> Result<()> {
        let keys: Vec<DieKey> = self.index.keys().copied().collect();
        for key in keys {
            let die = match self.index.get(&key) {
                Some(die) => die.clone(),
                None => continue,
            };
            match die.tag {
                constants::DW_TAG_variable => self.collect_variable(key, &die)?,
                constants::DW_TAG_subprogram => self.collect_subprogram(key, &die)?,
                _ => {}
            }
        }
        Ok(())
    }

    fn parent_tag(&self, die: &DieData<'a>) -> Option<DwTag> {
        self.index.get(&die.parent?).map(|parent| parent.tag)
    }

    fn is_global_scope(&self, die: &DieData<'a>) -> bool {
        matches!(
            self.parent_tag(die),
            Some(
                constants::DW_TAG_compile_unit
                    | constants::DW_TAG_partial_unit
                    | constants::DW_TAG_namespace
                    | constants::DW_TAG_class_type
                    | constants::DW_TAG_structure_type
                    | constants::DW_TAG_union_type
            )
        )
    }

    fn collect_variable(&mut self, key: DieKey, die: &DieData<'a>) -> Result<()> {
        if !self.is_global_scope(die) || die.flag(constants::DW_AT_declaration) {
            return Ok(());
        }
        let Some(name) = self.qualified_name(key) else {
            return Ok(());
        };
        let ty = self.type_reference(key, die)?;
        let address = self.static_address(die);
        let entry = GlobalSymbol { address, ty };
        match self.symbols.get(&name) {
            Some(existing) if existing.address.is_some() && address.is_none() => {}
            Some(existing) if existing.ty.is_none() && ty.is_some() => {
                self.symbols.insert(name, entry);
            }
            Some(_) => {}
            None => {
                self.symbols.insert(name, entry);
            }
        }
        Ok(())
    }

    /// Address of a global when the debug information gives a static one.
    fn static_address(&self, die: &DieData<'a>) -> Option<u64> {
        match die.attr(constants::DW_AT_location) {
            Some(AttributeValue::Exprloc(expression)) => self
                .evaluate_expression(die, expression)
                .ok()
                .and_then(|value| u64::try_from(value).ok()),
            Some(value) => match value {
                AttributeValue::Udata(value) => Some(value),
                AttributeValue::Data1(value) => Some(u64::from(value)),
                AttributeValue::Data2(value) => Some(u64::from(value)),
                AttributeValue::Data4(value) => Some(u64::from(value)),
                AttributeValue::Data8(value) => Some(value),
                AttributeValue::Sdata(value) => u64::try_from(value).ok(),
                _ => None,
            },
            None => None,
        }
    }

    fn collect_subprogram(&mut self, key: DieKey, die: &DieData<'a>) -> Result<()> {
        if !self.is_global_scope(die) {
            return Ok(());
        }
        let address = self.function_address(die);
        if die.flag(constants::DW_AT_declaration) && address.is_none() {
            return Ok(());
        }
        let Some(name) = self.qualified_name(key) else {
            return Ok(());
        };
        let signature = self.signature(key, die)?;
        let entry = GlobalFunction { address, signature };
        match self.functions.get(&name) {
            Some(existing) if existing.address.is_some() && address.is_none() => {}
            Some(_) => {}
            None => {
                self.functions.insert(name, entry);
            }
        }
        Ok(())
    }

    fn function_address(&self, die: &DieData<'a>) -> Option<u64> {
        match die.attr(constants::DW_AT_low_pc)? {
            AttributeValue::Addr(address) => Some(address),
            AttributeValue::DebugAddrIndex(index) => {
                self.dwarf.address(self.units.get(die.unit)?, index).ok()
            }
            _ => None,
        }
    }
}

enum MemberOutcome {
    Member(Option<Member>),
    Unsupported(String),
}

/// Little-endian / big-endian conversion of legacy `DW_AT_bit_offset` values.
struct BigEndianBitField {
    endian: Endian,
}

impl BigEndianBitField {
    fn checked_bit_field_start(
        &self,
        key: DieKey,
        data_offset: u64,
        storage_bytes: u64,
        old_offset: u64,
        length: u64,
    ) -> Result<u64> {
        let base = data_offset.checked_mul(8).ok_or_else(|| Error::Overflow {
            location: key.location(),
            what: "bit-field byte offset".to_string(),
        })?;
        if self.endian.is_big() {
            base.checked_add(old_offset).ok_or_else(|| Error::Overflow {
                location: key.location(),
                what: "bit-field start".to_string(),
            })
        } else {
            let storage_bits = storage_bytes
                .checked_mul(8)
                .ok_or_else(|| Error::Overflow {
                    location: key.location(),
                    what: "bit-field storage width".to_string(),
                })?;
            let start = base
                .checked_add(storage_bits)
                .and_then(|value| value.checked_sub(old_offset))
                .and_then(|value| value.checked_sub(length))
                .ok_or_else(|| Error::Overflow {
                    location: key.location(),
                    what: "little-endian bit-field start".to_string(),
                })?;
            Ok(start)
        }
    }
}

fn calling_convention(die: &DieData<'_>) -> Option<String> {
    match die.attr(constants::DW_AT_calling_convention)? {
        AttributeValue::CallingConvention(convention) => Some(match convention {
            constants::DW_CC_normal => "normal".to_string(),
            constants::DW_CC_program => "program".to_string(),
            constants::DW_CC_nocall => "nocall".to_string(),
            other => format!("{other:?}"),
        }),
        _ => None,
    }
}

fn int_value(value: i128) -> Result<IntValue> {
    if value < 0 {
        i64::try_from(value)
            .map(IntValue::Signed)
            .map_err(|_| Error::Message("enumerator value does not fit in 64 bits".to_string()))
    } else {
        u64::try_from(value)
            .map(IntValue::Unsigned)
            .map_err(|_| Error::Message("enumerator value does not fit in 64 bits".to_string()))
    }
}
