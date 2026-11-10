#![forbid(unsafe_code)]
//! `sym2isf` command line interface.
//!
//! The `dwarf` and `pdb` subcommands map directly onto [`sym2isf::convert`] and
//! [`sym2isf::IsfDocument::save`]. `dwarf-c` and `pdb-c` share the same
//! conversion, render C declarations for the named root types and have the
//! result compile-checked by an external TCC. There is no layout, query or
//! execution command. Exit codes: `0` success, `2` bad arguments (clap), `1`
//! conversion, generation, compilation or I/O failure. Standard output stays
//! empty on success; the artifact is the only output of a successful run.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, ExitCode};

use clap::{ArgGroup, Parser, Subcommand};
use sym2isf::c::Request;
use sym2isf::{DebugInput, Detail, Error, Result, convert};

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
    /// Declare PDB types and functions as C, checked by TCC before it is published.
    #[command(group(
        ArgGroup::new("selection")
            .required(true)
            .multiple(true)
            .args(["types", "functions", "all_functions"])
    ), group(
        ArgGroup::new("function_selection")
            .multiple(true)
            .args(["functions", "all_functions"])
    ))]
    PdbC {
        /// The `.pdb` file.
        pdb: PathBuf,
        /// Root type to declare, as named in the ISF tables; repeat per root.
        #[arg(long = "type", value_name = "NAME")]
        types: Vec<String>,
        /// Function to declare, as named in the ISF table; repeat per function.
        #[arg(long = "function", value_name = "NAME")]
        functions: Vec<String>,
        /// Declare every function signature in the input.
        #[arg(long)]
        all_functions: bool,
        /// Emit the recorded function addresses as a static data table.
        #[arg(long, requires = "function_selection")]
        with_addresses: bool,
        /// Output path for the generated C source; `.c` is recommended.
        #[arg(long)]
        output: PathBuf,
        /// TCC executable used to compile-check the generated translation unit.
        #[arg(long, default_value = "tcc")]
        tcc: PathBuf,
        /// PE image used for the preferred image base and the build id check.
        #[arg(long)]
        image: Option<PathBuf>,
        /// Explicit image base, decimal or `0x`-prefixed hexadecimal.
        #[arg(long, value_parser = parse_u64)]
        image_base: Option<u64>,
    },
    /// Declare DWARF types and functions as C, checked by TCC before it is published.
    #[command(group(
        ArgGroup::new("selection")
            .required(true)
            .multiple(true)
            .args(["types", "functions", "all_functions"])
    ), group(
        ArgGroup::new("function_selection")
            .multiple(true)
            .args(["functions", "all_functions"])
    ))]
    DwarfC {
        /// Image: executable, shared object, relocatable object or .dSYM bundle.
        image: PathBuf,
        /// Root type to declare, as named in the ISF tables; repeat per root.
        #[arg(long = "type", value_name = "NAME")]
        types: Vec<String>,
        /// Function to declare, as named in the ISF table; repeat per function.
        #[arg(long = "function", value_name = "NAME")]
        functions: Vec<String>,
        /// Declare every function signature in the input.
        #[arg(long)]
        all_functions: bool,
        /// Emit the recorded function addresses as a static data table.
        #[arg(long, requires = "function_selection")]
        with_addresses: bool,
        /// Output path for the generated C source; `.c` is recommended.
        #[arg(long)]
        output: PathBuf,
        /// TCC executable used to compile-check the generated translation unit.
        #[arg(long, default_value = "tcc")]
        tcc: PathBuf,
        /// Separate debug file, `.dSYM` bundle or split DWARF companion.
        #[arg(long)]
        debug_file: Option<PathBuf>,
        /// Select one architecture from a multi-slice container.
        #[arg(long)]
        architecture: Option<String>,
    },
}

/// Resolve a relative compiler path against the invoking directory.
///
/// The compiler runs with the temporary build directory as its working
/// directory, so `./tools/tcc` would otherwise be looked up there. A bare name
/// is left untouched so the operating system still searches `PATH`.
fn compiler_program(program: &Path) -> PathBuf {
    if program.is_absolute() || program.components().count() == 1 {
        return program.to_owned();
    }
    match std::env::current_dir() {
        Ok(directory) => directory.join(program),
        Err(_) => program.to_owned(),
    }
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
    let outcome = match cli.command {
        Command::PdbC {
            pdb,
            types,
            functions,
            all_functions,
            with_addresses,
            output,
            tcc,
            image,
            image_base,
        } => {
            let type_refs: Vec<&str> = types.iter().map(String::as_str).collect();
            let function_refs: Vec<&str> = functions.iter().map(String::as_str).collect();
            let request = Request {
                types: &type_refs,
                functions: &function_refs,
                all_functions,
                with_addresses,
            };
            run_c(
                DebugInput::Pdb {
                    pdb,
                    image,
                    image_base,
                    detail: detail_for(with_addresses, !functions.is_empty() || all_functions),
                },
                &request,
                &output,
                &tcc,
            )
        }
        Command::DwarfC {
            image,
            types,
            functions,
            all_functions,
            with_addresses,
            output,
            tcc,
            debug_file,
            architecture,
        } => {
            let type_refs: Vec<&str> = types.iter().map(String::as_str).collect();
            let function_refs: Vec<&str> = functions.iter().map(String::as_str).collect();
            let request = Request {
                types: &type_refs,
                functions: &function_refs,
                all_functions,
                with_addresses,
            };
            run_c(
                DebugInput::Dwarf {
                    image,
                    debug_file,
                    architecture,
                    detail: detail_for(with_addresses, !functions.is_empty() || all_functions),
                },
                &request,
                &output,
                &tcc,
            )
        }
        command => run_convert(command),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sym2isf: error {}: {error}", error.kind());
            ExitCode::from(1)
        }
    }
}

/// Convert one input to extended ISF and save it.
fn run_convert(command: Command) -> Result<()> {
    let (input, output) = match command {
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
                detail: if types_only {
                    Detail::TypesOnly
                } else {
                    Detail::Full
                },
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
                detail: if types_only {
                    Detail::TypesOnly
                } else {
                    Detail::Full
                },
            },
            output,
        ),
        Command::PdbC { .. } | Command::DwarfC { .. } => {
            unreachable!("the C commands have their own path")
        }
    };
    let document = convert(&input)?;
    let counts = format!(
        "{} base types, {} user types, {} enums, {} typedefs, {} symbols, {} functions",
        document.base_types.len(),
        document.user_types.len(),
        document.enums.len(),
        document.typedefs.len(),
        document.symbols.len(),
        document.functions.len(),
    );
    document.save(&output)?;
    eprintln!("sym2isf: wrote {counts} to {}", output.display());
    Ok(())
}

/// The conversion detail that can supply what the request asks for.
///
/// Declaring a function needs its signature but no address, so asking for
/// functions stays on `Signatures`; only the address table needs `Full`.
fn detail_for(with_addresses: bool, functions: bool) -> Detail {
    if with_addresses {
        Detail::Full
    } else if functions {
        Detail::Signatures
    } else {
        Detail::TypesOnly
    }
}

/// Render C for the request, compile it with TCC, then publish it.
///
/// The output is only created after TCC accepted the translation unit, and the
/// source is written with `create_new`, so a failed run never leaves a partial
/// or unverified file behind.
fn run_c(input: DebugInput, request: &Request<'_>, output: &Path, tcc: &Path) -> Result<()> {
    match std::fs::symlink_metadata(output) {
        Ok(_) => {
            return Err(Error::OutputExists {
                path: output.to_owned(),
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::io(output, error)),
    }

    let document = convert(&input)?;
    let source = sym2isf::c::generate(&document, request)?;

    let program = compiler_program(tcc);
    let directory = tempfile::Builder::new()
        .prefix("sym2isf-c")
        .tempdir()
        .map_err(|error| Error::io(std::env::temp_dir(), error))?;
    let source_path = directory.path().join("layout.c");
    std::fs::write(&source_path, source.as_bytes())
        .map_err(|error| Error::io(&source_path, error))?;
    let object_path = directory.path().join("layout.o");
    let compiled = Process::new(&program)
        .arg("-Werror")
        .arg("-c")
        .arg(&source_path)
        .arg("-o")
        .arg(&object_path)
        .current_dir(directory.path())
        .output()
        .map_err(|error| Error::TccCompile {
            executable: program.clone(),
            detail: error.to_string(),
        })?;
    if !compiled.status.success() {
        return Err(Error::TccCompile {
            executable: program.clone(),
            detail: format!(
                "{}\nstdout:\n{}\nstderr:\n{}",
                compiled.status,
                String::from_utf8_lossy(&compiled.stdout),
                String::from_utf8_lossy(&compiled.stderr)
            ),
        });
    }

    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Error::OutputExists {
                path: output.to_owned(),
            });
        }
        Err(error) => return Err(Error::io(output, error)),
    };
    if let Err(error) = file
        .write_all(source.as_bytes())
        .and_then(|()| file.flush())
    {
        drop(file);
        let _ = std::fs::remove_file(output);
        return Err(Error::io(output, error));
    }
    eprintln!(
        "sym2isf: wrote TCC-checked C source to {}",
        output.display()
    );
    Ok(())
}
