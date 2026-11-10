#![forbid(unsafe_code)]
//! `sym2isf` converts native DWARF and PDB debug information into the Ghidra
//! extended ISF document format.
//!
//! The crate is a pure frontend: it reads a debug container, normalizes the type
//! records it finds, and writes a JSON (or JSON.XZ) document. It also renders a
//! normalized document as C declarations ([`c::generate`]), which is a static
//! memory layout view rather than a layout engine: nothing here maps or reads
//! target memory, and there are no virtual-machine bindings.
//!
//! ```no_run
//! use std::path::PathBuf;
//! use sym2isf::{DebugInput, convert};
//!
//! let input = DebugInput::Dwarf {
//!     image: PathBuf::from("probe"),
//!     debug_file: None,
//!     architecture: None,
//!     detail: sym2isf::Detail::Full,
//! };
//! let document = convert(&input).expect("conversion");
//! document.save(std::path::Path::new("probe.json")).expect("write");
//! ```

pub mod c;
pub mod error;
pub mod isf;
pub mod normalize;

mod dwarf;
mod pdb;

use std::path::PathBuf;

pub use error::{Error, Result};
pub use isf::{
    BaseKind, BaseType, CompositeKind, Endian, EnumType, Field, Function, IntValue, IsfDocument,
    Metadata, Parameter, Producer, Qualifier, ReferenceKind, Symbol, Target, TypeRef, UserType,
};
pub use normalize::{
    ArrayRecord, BaseName, BaseRecord, BitfieldInfo, BitfieldSlice, CompositeRecord, EnumRecord,
    FunctionRecord, GlobalFunction, GlobalSymbol, Member, Node, Origin, PointerRecord,
    QualifiedRecord, TypeGraph, TypeId, TypedefRecord, bitfield_slice,
};

/// How much of the input a conversion publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detail {
    /// Types only: no symbols, no functions, no address conversion.
    TypesOnly,
    /// Types and function signatures, with no address on any record.
    ///
    /// Declaring a function needs its signature, not its location, so this mode
    /// works without an image base and on an unlinked object.
    Signatures,
    /// Types, function signatures, object symbols and addresses.
    Full,
}

impl Detail {
    /// True when addresses must be formed. A PDB then needs an image base and a
    /// relocatable object cannot provide one.
    pub fn needs_addresses(self) -> bool {
        matches!(self, Detail::Full)
    }

    /// True when procedure records are collected.
    pub fn wants_functions(self) -> bool {
        !matches!(self, Detail::TypesOnly)
    }

    /// True when object and public symbol records are collected.
    pub fn wants_symbols(self) -> bool {
        matches!(self, Detail::Full)
    }
}

/// A conversion request.
///
/// The format is chosen by the caller, never by sniffing the host operating
/// system, and the target ABI always comes from the input debug information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DebugInput {
    /// Native DWARF/ELF/Mach-O input.
    Dwarf {
        /// Executable, shared object, relocatable object or `.dSYM` companion.
        image: PathBuf,
        /// Optional separate debug file, `.dSYM` bundle or split DWARF companion.
        debug_file: Option<PathBuf>,
        /// Architecture to select from a multi-slice container.
        architecture: Option<String>,
        /// How much of the input to publish.
        detail: Detail,
    },
    /// Native PDB input.
    Pdb {
        /// The `.pdb` file.
        pdb: PathBuf,
        /// Optional PE image supplying the preferred image base and build id.
        image: Option<PathBuf>,
        /// Explicit image base overriding the preferred one.
        image_base: Option<u64>,
        /// How much of the input to publish.
        detail: Detail,
    },
}

/// Convert one input to an extended ISF document.
///
/// The returned document is already normalized and validated; it never executes
/// or maps the target program.
pub fn convert(input: &DebugInput) -> Result<IsfDocument> {
    match input {
        DebugInput::Dwarf {
            image,
            debug_file,
            architecture,
            detail,
        } => dwarf::convert(
            image,
            debug_file.as_deref(),
            architecture.as_deref(),
            *detail,
        ),
        DebugInput::Pdb {
            pdb,
            image,
            image_base,
            detail,
        } => pdb::convert(pdb, image.as_deref(), *image_base, *detail),
    }
}
