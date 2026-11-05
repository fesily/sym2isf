//! Error type shared by the library, the frontends and the CLI.
//!
//! Every failure that is not a caller mistake carries the input path or the
//! debug record it came from, so that a failed conversion is actionable without
//! re-running the parser.

use std::path::PathBuf;

/// Result alias used across the crate; the error type stays overridable.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// All failures a conversion can produce.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Filesystem failure on an input or output path.
    #[error("i/o error on {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying operating system error.
        #[source]
        source: std::io::Error,
    },

    /// The requested output file already exists; existing files are never overwritten.
    #[error("output already exists: {path}")]
    OutputExists {
        /// Existing path.
        path: PathBuf,
    },

    /// The output path does not end in `.json` or `.json.xz`.
    #[error("unsupported output path {path}: expected a `.json` or `.json.xz` suffix")]
    UnsupportedOutput {
        /// Rejected path.
        path: PathBuf,
    },

    /// The input carries no debug type information.
    #[error("no debug type information in {path}")]
    NoDebugInfo {
        /// Input path.
        path: PathBuf,
    },

    /// The container or its debug sections could not be decoded.
    #[error("cannot parse {path}: {detail}")]
    Corrupt {
        /// Input path.
        path: PathBuf,
        /// What failed.
        detail: String,
    },

    /// The container itself is not a supported object format.
    #[error("unsupported container {path}: {detail}")]
    UnsupportedContainer {
        /// Input path.
        path: PathBuf,
        /// What failed.
        detail: String,
    },

    /// Split/supplementary DWARF is required but was not supplied.
    #[error("{path} requires missing debug companion `{companion}`; pass it explicitly")]
    MissingDebugCompanion {
        /// Input path.
        path: PathBuf,
        /// Companion path or name recorded in the debug information.
        companion: String,
    },

    /// A relocation kind appears that this frontend cannot apply.
    #[error("unsupported {section} relocation {kind} at offset {offset:#x} in {path}")]
    UnsupportedRelocation {
        /// Input path.
        path: PathBuf,
        /// Section holding the relocation.
        section: String,
        /// Offset of the relocated field.
        offset: u64,
        /// Relocation kind as reported by the object reader.
        kind: String,
    },

    /// A multi-architecture container needs an explicit slice selection.
    #[error("{path} contains several architectures {candidates:?}; pass one of them explicitly")]
    AmbiguousArchitecture {
        /// Input path.
        path: PathBuf,
        /// Architectures present in the container.
        candidates: Vec<String>,
    },

    /// The requested architecture is not present.
    #[error("{path} has no {requested} slice; candidates {candidates:?}")]
    UnknownArchitecture {
        /// Input path.
        path: PathBuf,
        /// Requested architecture name.
        requested: String,
        /// Architectures present in the container.
        candidates: Vec<String>,
    },

    /// Image and separate debug file describe different builds.
    #[error("{image} and {debug_file} do not match: {detail}")]
    DebugFileMismatch {
        /// Image path.
        image: PathBuf,
        /// Separate debug file path.
        debug_file: PathBuf,
        /// What differed.
        detail: String,
    },

    /// A relocatable object has no link-time addresses.
    #[error("{path} is an unlinked object with no fixed addresses; convert it with --types-only")]
    UnlinkedImage {
        /// Input path.
        path: PathBuf,
    },

    /// A record cannot be represented without inventing layout.
    #[error("{location}: layout cannot be represented statically: {detail}")]
    UnsupportedLayout {
        /// Debug record that triggered the failure.
        location: String,
        /// Why it cannot be represented.
        detail: String,
    },

    /// A PDB-only conversion needs the image base to form absolute addresses.
    #[error("a PDB-only conversion needs --image-base (or --image) to form absolute addresses")]
    MissingImageBase,

    /// Several incompatible definitions claim the same name.
    #[error("ambiguous definition of `{name}`: {detail}")]
    AmbiguousDefinition {
        /// Conflicting name.
        name: String,
        /// Description of the candidates.
        detail: String,
    },

    /// A PDB type record is not supported by this frontend.
    #[error("unsupported PDB record: {detail}")]
    UnsupportedPdbRecord {
        /// Stream/type index plus what is missing.
        detail: String,
    },

    /// The target machine type is unknown.
    #[error("unsupported target machine type {machine}")]
    UnsupportedTarget {
        /// Machine type as reported by the file or PDB.
        machine: String,
    },

    /// Checked arithmetic failed while normalizing sizes or offsets.
    #[error("{location}: arithmetic overflow while computing {what}")]
    Overflow {
        /// Debug record that triggered the failure.
        location: String,
        /// Quantity being computed.
        what: String,
    },

    /// The produced document violates the output contract.
    #[error("invalid ISF document: {0}")]
    InvalidDocument(String),

    /// JSON encoding or decoding failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// XZ compression failed.
    #[error("xz compression error: {0}")]
    Compression(String),

    /// Anything else with a rendered explanation.
    #[error("{0}")]
    Message(String),
}

impl Error {
    /// Attach a path to a plain I/O error.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    /// Stable machine-readable discriminant, used by tests and the CLI.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Io { .. } => "Io",
            Error::OutputExists { .. } => "OutputExists",
            Error::UnsupportedOutput { .. } => "UnsupportedOutput",
            Error::NoDebugInfo { .. } => "NoDebugInfo",
            Error::Corrupt { .. } => "Corrupt",
            Error::UnsupportedContainer { .. } => "UnsupportedContainer",
            Error::MissingDebugCompanion { .. } => "MissingDebugCompanion",
            Error::UnsupportedRelocation { .. } => "UnsupportedRelocation",
            Error::AmbiguousArchitecture { .. } => "AmbiguousArchitecture",
            Error::UnknownArchitecture { .. } => "UnknownArchitecture",
            Error::DebugFileMismatch { .. } => "DebugFileMismatch",
            Error::UnlinkedImage { .. } => "UnlinkedImage",
            Error::UnsupportedLayout { .. } => "UnsupportedLayout",
            Error::MissingImageBase => "MissingImageBase",
            Error::AmbiguousDefinition { .. } => "AmbiguousDefinition",
            Error::UnsupportedPdbRecord { .. } => "UnsupportedPdbRecord",
            Error::UnsupportedTarget { .. } => "UnsupportedTarget",
            Error::Overflow { .. } => "Overflow",
            Error::InvalidDocument(_) => "InvalidDocument",
            Error::Json(_) => "Json",
            Error::Compression(_) => "Compression",
            Error::Message(_) => "Message",
        }
    }
}
