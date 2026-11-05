#![forbid(unsafe_code)]
//! `sym2isf` command line interface.
//!
//! Two subcommands map directly onto [`sym2isf::convert`] and
//! [`sym2isf::IsfDocument::save`]; there is no layout, query or execution
//! command. Exit codes: `0` success, `2` bad arguments (clap), `1` conversion or
//! I/O failure. Standard output stays empty on success; the artifact is the only
//! output of a successful run.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sym2isf::{DebugInput, convert};

#[derive(Parser)]
#[command(
    name = "sym2isf",
    version,
    about = "Convert native DWARF or PDB debug information into extended ISF",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Convert DWARF debug information from an ELF or Mach-O image.
    Dwarf {
        /// Image: executable, shared object, relocatable object or .dSYM bundle.
        image: PathBuf,
        /// Output path; the suffix selects `.json` or `.json.xz`.
        #[arg(long)]
        output: PathBuf,
        /// Separate debug file, `.dSYM` bundle or split DWARF companion.
        #[arg(long)]
        debug_file: Option<PathBuf>,
        /// Select one architecture from a multi-slice container.
        #[arg(long)]
        architecture: Option<String>,
        /// Emit types only: no symbols and no functions.
        #[arg(long)]
        types_only: bool,
    },
    /// Convert a PDB into extended ISF.
    Pdb {
        /// The `.pdb` file.
        pdb: PathBuf,
        /// Output path; the suffix selects `.json` or `.json.xz`.
        #[arg(long)]
        output: PathBuf,
        /// PE image used for the preferred image base and the build id check.
        #[arg(long)]
        image: Option<PathBuf>,
        /// Explicit image base, decimal or `0x`-prefixed hexadecimal.
        #[arg(long, value_parser = parse_u64)]
        image_base: Option<u64>,
        /// Emit types only: no symbols, no functions, no address conversion.
        #[arg(long)]
        types_only: bool,
    },
}

fn parse_u64(raw: &str) -> std::result::Result<u64, String> {
    let trimmed = raw.trim();
    let parsed = match trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => trimmed.parse::<u64>(),
    };
    parsed.map_err(|e| format!("`{raw}` is not a decimal or 0x-prefixed 64-bit value: {e}"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (input, output) = match cli.command {
        Command::Dwarf {
            image,
            output,
            debug_file,
            architecture,
            types_only,
        } => (
            DebugInput::Dwarf {
                image,
                debug_file,
                architecture,
                types_only,
            },
            output,
        ),
        Command::Pdb {
            pdb,
            output,
            image,
            image_base,
            types_only,
        } => (
            DebugInput::Pdb {
                pdb,
                image,
                image_base,
                types_only,
            },
            output,
        ),
    };

    match convert(&input) {
        Ok(document) => {
            let counts = format!(
                "{} base types, {} user types, {} enums, {} typedefs, {} symbols, {} functions",
                document.base_types.len(),
                document.user_types.len(),
                document.enums.len(),
                document.typedefs.len(),
                document.symbols.len(),
                document.functions.len(),
            );
            match document.save(&output) {
                Ok(()) => {
                    eprintln!("sym2isf: wrote {counts} to {}", output.display());
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("sym2isf: error {}: {error}", error.kind());
                    ExitCode::from(1)
                }
            }
        }
        Err(error) => {
            eprintln!("sym2isf: error {}: {error}", error.kind());
            ExitCode::from(1)
        }
    }
}
