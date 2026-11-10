#![forbid(unsafe_code)]
//! `sym2isf` command line interface.
//!
//! The `dwarf` and `pdb` subcommands map directly onto [`sym2isf::convert`] and
//! [`sym2isf::IsfDocument::save`]. `dwarf-c` and `pdb-c` share the same
//! conversion, render declarations for the named root types and have the result
//! compile-checked by an external TCC (layout and SDK views) or load-checked by
//! an external LuaJIT (the FFI module). There is no layout, query or execution
//! command. Exit codes: `0` success, `2` bad arguments (clap), `1`
//! conversion, generation, compilation or I/O failure. Standard output stays
//! empty on success; the artifact is the only output of a successful run.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, ExitCode};

use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use sym2isf::c::{FfiRequest, Request, View};
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

/// Which product a C subcommand writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Emit {
    /// Byte-exact memory layout with prefixed names and `extern` prototypes.
    Layout,
    /// Source names plus one `struct s2c_api` of function pointers and a binder.
    Sdk,
    /// A LuaJIT FFI module: prefixed cdef declarations, exact bit-field
    /// accessors and a binder that asks the caller's resolver for each address.
    Ffi,
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
    /// Declare PDB types and functions as C or as a LuaJIT FFI module, checked
    /// by TCC or LuaJIT before it is published.
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
        /// Emit the recorded addresses as a static data table (layout view only).
        #[arg(long, requires = "function_selection")]
        with_addresses: bool,
        /// Product to write: the layout view (default), a callable SDK or a
        /// LuaJIT FFI module.
        #[arg(
            long,
            value_enum,
            default_value_t = Emit::Layout,
            requires_if("sdk", "function_selection")
        )]
        emit: Emit,
        /// Allow aggregates passed or returned by value (SDK and FFI views).
        #[arg(long)]
        allow_by_value_aggregates: bool,
        /// Output path for the artifact; `.c`, `.h` or `.lua` as appropriate.
        #[arg(long)]
        output: PathBuf,
        /// TCC executable used to compile-check the layout and SDK views.
        #[arg(long, default_value = "tcc")]
        tcc: PathBuf,
        /// LuaJIT executable used to check the module; only used by `--emit ffi`.
        #[arg(long, default_value = "luajit")]
        luajit: PathBuf,
        /// PE image used for the preferred image base and the build id check.
        #[arg(long)]
        image: Option<PathBuf>,
        /// Explicit image base, decimal or `0x`-prefixed hexadecimal.
        #[arg(long, value_parser = parse_u64)]
        image_base: Option<u64>,
    },
    /// Declare DWARF types and functions as C or as a LuaJIT FFI module, checked
    /// by TCC or LuaJIT before it is published.
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
        /// Emit the recorded addresses as a static data table (layout view only).
        #[arg(long, requires = "function_selection")]
        with_addresses: bool,
        /// Product to write: the layout view (default), a callable SDK or a
        /// LuaJIT FFI module.
        #[arg(
            long,
            value_enum,
            default_value_t = Emit::Layout,
            requires_if("sdk", "function_selection")
        )]
        emit: Emit,
        /// Allow aggregates passed or returned by value (SDK and FFI views).
        #[arg(long)]
        allow_by_value_aggregates: bool,
        /// Output path for the artifact; `.c`, `.h` or `.lua` as appropriate.
        #[arg(long)]
        output: PathBuf,
        /// TCC executable used to compile-check the layout and SDK views.
        #[arg(long, default_value = "tcc")]
        tcc: PathBuf,
        /// LuaJIT executable used to check the module; only used by `--emit ffi`.
        #[arg(long, default_value = "luajit")]
        luajit: PathBuf,
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
    reject_address_table_with_ffi(&cli.command);
    let outcome = match cli.command {
        Command::PdbC {
            pdb,
            types,
            functions,
            all_functions,
            with_addresses,
            emit,
            allow_by_value_aggregates,
            output,
            tcc,
            luajit,
            image,
            image_base,
        } => run_declarations(
            DebugInput::Pdb {
                pdb,
                image,
                image_base,
                detail: detail_for(emit, with_addresses, !functions.is_empty() || all_functions),
            },
            emit,
            Selection {
                types,
                functions,
                all_functions,
                with_addresses,
                allow_by_value_aggregates,
            },
            &output,
            &tcc,
            &luajit,
        ),
        Command::DwarfC {
            image,
            types,
            functions,
            all_functions,
            with_addresses,
            emit,
            allow_by_value_aggregates,
            output,
            tcc,
            luajit,
            debug_file,
            architecture,
        } => run_declarations(
            DebugInput::Dwarf {
                image,
                debug_file,
                architecture,
                detail: detail_for(emit, with_addresses, !functions.is_empty() || all_functions),
            },
            emit,
            Selection {
                types,
                functions,
                all_functions,
                with_addresses,
                allow_by_value_aggregates,
            },
            &output,
            &tcc,
            &luajit,
        ),
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

/// The declarations one C subcommand was asked for.
struct Selection {
    types: Vec<String>,
    functions: Vec<String>,
    all_functions: bool,
    with_addresses: bool,
    allow_by_value_aggregates: bool,
}

/// `--with-addresses` is the layout view's data table; an FFI module has no
/// such table, and ignoring the flag would claim it was honoured.
fn reject_address_table_with_ffi(command: &Command) {
    let (with_addresses, emit) = match command {
        Command::PdbC {
            with_addresses,
            emit,
            ..
        }
        | Command::DwarfC {
            with_addresses,
            emit,
            ..
        } => (*with_addresses, *emit),
        _ => return,
    };
    if with_addresses && emit == Emit::Ffi {
        <Cli as clap::CommandFactory>::command()
            .error(
                clap::error::ErrorKind::ArgumentConflict,
                "--with-addresses cannot be used with --emit ffi",
            )
            .exit();
    }
}

/// Render the requested product, then check and publish it.
#[allow(clippy::too_many_arguments)]
fn run_declarations(
    input: DebugInput,
    emit: Emit,
    selection: Selection,
    output: &Path,
    tcc: &Path,
    luajit: &Path,
) -> Result<()> {
    let types: Vec<&str> = selection.types.iter().map(String::as_str).collect();
    let functions: Vec<&str> = selection.functions.iter().map(String::as_str).collect();
    match view_for(emit) {
        Some(view) => {
            let request = Request {
                types: &types,
                functions: &functions,
                all_functions: selection.all_functions,
                with_addresses: selection.with_addresses,
                view,
                allow_by_value_aggregates: selection.allow_by_value_aggregates,
            };
            run_c(input, &request, output, tcc)
        }
        None => {
            let request = FfiRequest {
                types: &types,
                functions: &functions,
                all_functions: selection.all_functions,
                allow_by_value_aggregates: selection.allow_by_value_aggregates,
            };
            run_ffi(input, &request, output, luajit)
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
fn detail_for(emit: Emit, with_addresses: bool, functions: bool) -> Detail {
    // The SDK view and the FFI binder hand every member's offset to the
    // caller's resolver, so selecting functions needs the recorded addresses; a
    // types-only module and the layout view keep them optional.
    if emit == Emit::Ffi {
        return if functions {
            Detail::Full
        } else {
            Detail::TypesOnly
        };
    }
    if emit == Emit::Sdk || with_addresses {
        Detail::Full
    } else if functions {
        Detail::Signatures
    } else {
        Detail::TypesOnly
    }
}

/// The C product a flag selects, or `None` for the LuaJIT module.
fn view_for(emit: Emit) -> Option<View> {
    match emit {
        Emit::Layout => Some(View::Layout),
        Emit::Sdk => Some(View::Sdk),
        Emit::Ffi => None,
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

    publish(output, source.as_bytes())?;
    eprintln!(
        "sym2isf: wrote TCC-checked C source to {}",
        output.display()
    );
    Ok(())
}

/// Write a checked artifact, never replacing an existing file.
///
/// The file is created with `create_new`, so a concurrent writer wins the race
/// instead of being overwritten, and a failed write removes the file this run
/// created rather than leaving a truncated one behind.
fn publish(output: &Path, bytes: &[u8]) -> Result<()> {
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
    if let Err(error) = file.write_all(bytes).and_then(|()| file.flush()) {
        drop(file);
        let _ = std::fs::remove_file(output);
        return Err(Error::io(output, error));
    }
    Ok(())
}

/// Render a LuaJIT FFI module, check it with a real interpreter, then publish it.
///
/// The module only registers and validates its declarations at load time: it
/// never opens the input image, so checking it cannot execute target code. A
/// module that the interpreter rejects is never published, and there is no flag
/// that skips the check.
fn run_ffi(
    input: DebugInput,
    request: &FfiRequest<'_>,
    output: &Path,
    luajit: &Path,
) -> Result<()> {
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
    let module = sym2isf::c::generate_ffi(&document, request)?;

    let program = compiler_program(luajit);
    let directory = tempfile::Builder::new()
        .prefix("sym2isf-ffi")
        .tempdir()
        .map_err(|error| Error::io(std::env::temp_dir(), error))?;
    let module_path = directory.path().join("module.lua");
    std::fs::write(&module_path, module.as_bytes())
        .map_err(|error| Error::io(&module_path, error))?;
    let checked = Process::new(&program)
        .arg("module.lua")
        .current_dir(directory.path())
        .output()
        .map_err(|error| Error::LuaJitCheck {
            executable: program.clone(),
            detail: error.to_string(),
        })?;
    if !checked.status.success() {
        return Err(Error::LuaJitCheck {
            executable: program.clone(),
            detail: format!(
                "{}\nstdout:\n{}\nstderr:\n{}",
                checked.status,
                String::from_utf8_lossy(&checked.stdout),
                String::from_utf8_lossy(&checked.stderr)
            ),
        });
    }

    publish(output, module.as_bytes())?;
    eprintln!(
        "sym2isf: wrote LuaJIT-checked FFI module to {}",
        output.display()
    );
    Ok(())
}
