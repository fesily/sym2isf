// The harness is platform-gated: a helper that this target never calls is still
// used by the Unix-only or Windows-only cases, so a dead-code warning here would
// only be noise.
#![allow(dead_code)]

//! Native acceptance tests: real compiler output in, extended ISF out.
//!
//! Every case here compiles a fixture, converts the produced debug information
//! with the real CLI, and compares the document against what the compiler
//! actually laid out. External tools are optional locally and mandatory in CI
//! (`SYM2ISF_NATIVE_TESTS=1` makes a missing tool or artifact a failure).

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use object::{Object, ObjectSection, ObjectSymbol};
use serde_json::Value;
use sym2isf::{Endian, IsfDocument};

const PROBE_C: &str = "tests/fixtures/layout_probe.c";
const PROBE_HEADER_DIR: &str = "tests/fixtures";
const PDB_PROBE_C: &str = "tests/fixtures/pdb_probe.c";
const CPP_PROBE: &str = "tests/fixtures/layout_probe.cpp";
const BE_PROBE: &str = "tests/fixtures/bitfield_be.c";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn native_required() -> bool {
    matches!(std::env::var("SYM2ISF_NATIVE_TESTS").as_deref(), Ok("1"))
}

fn find_tool(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = directory.join(format!("{name}.exe"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Resolve a tool, or explain why the case is skipped.
fn tool(name: &str) -> Option<PathBuf> {
    match find_tool(name) {
        Some(path) => Some(path),
        None if native_required() => {
            panic!("SYM2ISF_NATIVE_TESTS=1 but `{name}` is not on PATH")
        }
        None => {
            eprintln!("skipping: `{name}` is not available");
            None
        }
    }
}

/// Resolve the first available spelling of a tool.
fn tool_any(names: &[&str]) -> Option<PathBuf> {
    for name in names {
        if let Some(path) = find_tool(name) {
            return Some(path);
        }
    }
    if native_required() {
        panic!("SYM2ISF_NATIVE_TESTS=1 but none of {names:?} is on PATH");
    }
    eprintln!("skipping: none of {names:?} is available");
    None
}

fn compile(command: &mut Command) -> bool {
    let output = command
        .output()
        .unwrap_or_else(|e| panic!("cannot run {command:?}: {e}"));
    if !output.status.success() {
        panic!(
            "compilation failed: {command:?}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    true
}

fn run_binary(path: &Path) -> String {
    let output = Command::new(path)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", path.display()));
    assert!(
        output.status.success(),
        "{} failed: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

struct CliOutput {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

impl CliOutput {
    fn success(&self) -> bool {
        self.status == Some(0)
    }
    fn describe(&self) -> String {
        format!(
            "status {:?}\nstdout: {}\nstderr: {}",
            self.status,
            String::from_utf8_lossy(&self.stdout),
            self.stderr
        )
    }
}

fn cli<I, S>(args: I) -> CliOutput
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    cli_in(None, args)
}

/// Run the CLI in `directory`, when given, as its working directory.
fn cli_in<I, S>(directory: Option<&Path>, args: I) -> CliOutput
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(env!("CARGO_BIN_EXE_sym2isf"));
    command.args(args);
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    let output = command.output().expect("run sym2isf");
    CliOutput {
        status: output.status.code(),
        stdout: output.stdout,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn convert(input: &Path, output: &Path, extra: &[&str]) -> CliOutput {
    let mut args: Vec<&OsStr> = vec![
        OsStr::new("dwarf"),
        input.as_os_str(),
        OsStr::new("--output"),
        output.as_os_str(),
    ];
    for value in extra {
        args.push(OsStr::new(value));
    }
    cli(args)
}

fn convert_pdb(pdb: &Path, output: &Path, extra: &[&str]) -> CliOutput {
    let mut args: Vec<&OsStr> = vec![
        OsStr::new("pdb"),
        pdb.as_os_str(),
        OsStr::new("--output"),
        output.as_os_str(),
    ];
    for value in extra {
        args.push(OsStr::new(value));
    }
    cli(args)
}

/// Convert a linked executable.
///
/// Apple's linker keeps DWARF in the object files, so on macOS the matching dSYM
/// bundle is handed to the converter; elsewhere the executable carries the debug
/// information itself.
fn convert_binary(input: &Path, output: &Path) -> CliOutput {
    #[cfg(target_os = "macos")]
    let extra: Vec<String> = {
        let dsymutil = find_tool("dsymutil").unwrap_or_else(|| {
            panic!("SYM2ISF_NATIVE_TESTS requires dsymutil on macOS");
        });
        let bundle = input.with_extension("dSYM");
        compile(Command::new(dsymutil).arg(input).arg("-o").arg(&bundle));
        vec![
            "--debug-file".to_string(),
            bundle.to_string_lossy().into_owned(),
        ]
    };
    #[cfg(not(target_os = "macos"))]
    let extra: Vec<String> = Vec::new();
    let borrowed: Vec<&str> = extra.iter().map(String::as_str).collect();
    convert(input, output, &borrowed)
}

/// True when the given clang build can emit code for `target`.
fn clang_has_target(clang: &Path, target: &str) -> bool {
    let output = Command::new(clang).arg("--print-targets").output();
    match output {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
            text.contains(target)
        }
        _ => false,
    }
}

fn load_document(path: &Path) -> Value {
    let bytes =
        std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()))
}

fn load_typed(path: &Path) -> IsfDocument {
    let bytes = std::fs::read(path).unwrap();
    serde_json::from_slice(&bytes).expect("document round-trips")
}

fn tempdir(tag: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "sym2isf-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&directory).expect("temp dir");
    directory
}

// ---------------------------------------------------------------------------
// Oracle
// ---------------------------------------------------------------------------

struct Oracle {
    pointer_size: u64,
    endian: String,
    sizes: BTreeMap<String, u64>,
    offsets: BTreeMap<String, BTreeMap<String, u64>>,
    bits_bytes: Vec<u8>,
    bits_values: BTreeMap<String, i64>,
    addresses: BTreeMap<String, u64>,
}

impl Oracle {
    fn parse(json: &str) -> Oracle {
        let value: Value = serde_json::from_str(json).expect("probe prints JSON");
        let mut sizes = BTreeMap::new();
        for (name, size) in value["sizeof"].as_object().expect("sizeof") {
            sizes.insert(name.clone(), size.as_u64().expect("size"));
        }
        let mut offsets = BTreeMap::new();
        for (aggregate, fields) in value["offsetof"].as_object().expect("offsetof") {
            let mut map = BTreeMap::new();
            for (field, offset) in fields.as_object().expect("fields") {
                map.insert(field.clone(), offset.as_u64().expect("offset"));
            }
            offsets.insert(aggregate.clone(), map);
        }
        let bits_bytes = value["bits_bytes"]
            .as_str()
            .expect("bits_bytes")
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let mut bits_values = BTreeMap::new();
        for (name, bit) in value["bits_values"].as_object().expect("bits_values") {
            bits_values.insert(name.clone(), bit.as_i64().expect("bit value"));
        }
        let mut addresses = BTreeMap::new();
        for (name, address) in value["address"].as_object().expect("address") {
            addresses.insert(name.clone(), address.as_u64().expect("address"));
        }
        Oracle {
            pointer_size: value["pointer_size"].as_u64().expect("pointer_size"),
            endian: value["endian"].as_str().expect("endian").to_string(),
            sizes,
            offsets,
            bits_bytes,
            bits_values,
            addresses,
        }
    }
}

// ---------------------------------------------------------------------------
// Document inspection helpers
// ---------------------------------------------------------------------------

fn field<'a>(document: &'a Value, aggregate: &str, member: &str) -> &'a Value {
    &document["user_types"][aggregate]["fields"][member]
}

fn field_offset(document: &Value, aggregate: &str, member: &str) -> u64 {
    field(document, aggregate, member)["offset"]
        .as_u64()
        .unwrap_or_else(|| panic!("{aggregate}.{member} has no offset"))
}

fn resolve_base<'a>(document: &'a Value, name: &str) -> &'a Value {
    document["base_types"]
        .get(name)
        .unwrap_or_else(|| panic!("base type {name} is missing"))
}

/// Decode a bit-field exactly the way the emitted reference describes it.
fn decode_bitfield(
    bytes: &[u8],
    offset: u64,
    storage_size: u64,
    endian: Endian,
    bit_position: u64,
    bit_length: u64,
    signed: bool,
) -> i128 {
    let start = usize::try_from(offset).expect("offset fits");
    let len = usize::try_from(storage_size).expect("size fits");
    let slice = &bytes[start..start + len];
    let raw = match endian {
        Endian::Little => slice
            .iter()
            .rev()
            .fold(0u128, |acc, byte| (acc << 8) | u128::from(*byte)),
        Endian::Big => slice
            .iter()
            .fold(0u128, |acc, byte| (acc << 8) | u128::from(*byte)),
    };
    let value = (raw >> bit_position) & ((1u128 << bit_length) - 1);
    if signed && bit_length > 0 && (value >> (bit_length - 1)) & 1 == 1 {
        (value as i128) - (1i128 << bit_length)
    } else {
        value as i128
    }
}

/// Everything the wire format says about one bit-field.
struct Bitfield {
    offset: u64,
    storage_size: u64,
    endian: Endian,
    bit_position: u64,
    bit_length: u64,
    signed: bool,
}

fn bitfield_of(document: &Value, aggregate: &str, member: &str) -> Bitfield {
    let entry = field(document, aggregate, member);
    let ty = &entry["type"];
    assert_eq!(
        ty["kind"], "bitfield",
        "{aggregate}.{member} must be a bit-field"
    );
    let storage_name = ty["type"]["name"].as_str().expect("storage base name");
    let storage = resolve_base(document, storage_name);
    let endian = match storage["endian"].as_str().expect("endian") {
        "little" => Endian::Little,
        other => {
            assert_eq!(other, "big");
            Endian::Big
        }
    };
    Bitfield {
        offset: entry["offset"].as_u64().expect("bit-field offset"),
        storage_size: storage["size"].as_u64().expect("storage size"),
        endian,
        bit_position: ty["bit_position"].as_u64().expect("bit_position"),
        bit_length: ty["bit_length"].as_u64().expect("bit_length"),
        signed: storage["signed"].as_bool().unwrap_or(false),
    }
}

impl Bitfield {
    fn decode(&self, bytes: &[u8]) -> i128 {
        decode_bitfield(
            bytes,
            self.offset,
            self.storage_size,
            self.endian,
            self.bit_position,
            self.bit_length,
            self.signed,
        )
    }
}

// ---------------------------------------------------------------------------
// Shared assertions
// ---------------------------------------------------------------------------

fn assert_target_metadata(document: &Value, architecture: &str, oracle: &Oracle) {
    let target = &document["metadata"]["sym2isf"]["target"];
    assert_eq!(document["metadata"]["format"], "6.2.0");
    assert_eq!(document["metadata"]["producer"]["name"], "sym2isf");
    assert_eq!(target["architecture"], architecture);
    assert_eq!(target["pointer_size"].as_u64(), Some(oracle.pointer_size));
    assert_eq!(target["endian"].as_str(), Some(oracle.endian.as_str()));
}

fn assert_probe_layout(document: &Value, oracle: &Oracle, architecture: &str) {
    assert_target_metadata(document, architecture, oracle);

    for (name, size) in &oracle.sizes {
        let expected = *size;
        let actual = document["user_types"][name]["size"]
            .as_u64()
            .unwrap_or_else(|| panic!("aggregate {name} is missing"));
        assert_eq!(actual, expected, "sizeof({name})");
    }

    for (aggregate, fields) in &oracle.offsets {
        for (member, offset) in fields {
            assert_eq!(
                field_offset(document, aggregate, member),
                *offset,
                "offsetof({aggregate}.{member})"
            );
        }
    }

    // Recursive pointer: Node.next points back at Node.
    let next = field(document, "Node", "next");
    assert_eq!(next["type"]["kind"], "pointer");
    assert_eq!(next["type"]["subtype"]["kind"], "struct");
    assert_eq!(next["type"]["subtype"]["name"], "Node");

    // Packet.next points back at Packet, nodes is Node[2], matrix is uint16[2][3].
    assert_eq!(
        field(document, "Packet", "next")["type"]["subtype"]["name"],
        "Packet"
    );
    let nodes = &field(document, "Packet", "nodes")["type"];
    assert_eq!(nodes["kind"], "array");
    assert_eq!(nodes["count"].as_u64(), Some(2));
    assert_eq!(nodes["subtype"]["name"], "Node");
    let matrix = &field(document, "Packet", "matrix")["type"];
    assert_eq!(matrix["kind"], "array");
    assert_eq!(matrix["count"].as_u64(), Some(2), "outer matrix dimension");
    assert_eq!(matrix["subtype"]["kind"], "array");
    assert_eq!(
        matrix["subtype"]["count"].as_u64(),
        Some(3),
        "inner matrix dimension"
    );

    // The callback keeps its full signature.
    let callback = &field(document, "Packet", "callback")["type"];
    assert_eq!(callback["kind"], "pointer");
    let signature = &callback["subtype"];
    assert_eq!(signature["kind"], "function");
    let parameters = signature["parameters"].as_array().expect("parameters");
    assert_eq!(parameters.len(), 2);
    assert_eq!(parameters[0]["type"]["kind"], "pointer");
    assert_eq!(parameters[0]["type"]["subtype"]["name"], "Packet");
    assert_eq!(parameters[1]["type"]["kind"], "typedef");

    // Enum constants are exact and signed.
    let code = &document["enums"]["SignedCode"];
    assert_eq!(code["constants"]["CODE_NEG"].as_i64(), Some(-3));
    assert_eq!(code["constants"]["CODE_POS"].as_i64(), Some(7));
    assert_eq!(code["size"].as_u64(), Some(4));
    assert_eq!(field(document, "Packet", "code")["type"]["kind"], "enum");

    // Packed layout keeps its unaligned offset.
    assert_eq!(field_offset(document, "Packed", "value"), 1);
    assert_eq!(document["user_types"]["Packed"]["size"].as_u64(), Some(5));

    // Union members overlap at offset zero.
    assert_eq!(field_offset(document, "Value", "word"), 0);
    assert_eq!(field_offset(document, "Value", "bytes"), 0);

    // Bit-fields: the emitted parameters must reproduce the probe's bytes.
    let mut rebuilt = oracle.bits_bytes.clone();
    for member in ["pad", "field", "tail"] {
        let bitfield = bitfield_of(document, "Bits", member);
        let raw = bitfield.decode(&oracle.bits_bytes);
        assert_eq!(
            raw,
            i128::from(oracle.bits_values[member]),
            "bit-field {member} decoded from the probe bytes"
        );
        // Write the value back so the whole buffer can be compared again.
        let mask = ((1u128 << bitfield.bit_length) - 1) << bitfield.bit_position;
        let start = usize::try_from(bitfield.offset).expect("offset");
        let len = usize::try_from(bitfield.storage_size).expect("storage");
        let storage = match bitfield.endian {
            Endian::Little => rebuilt[start..start + len]
                .iter()
                .rev()
                .fold(0u128, |acc, byte| (acc << 8) | u128::from(*byte)),
            Endian::Big => rebuilt[start..start + len]
                .iter()
                .fold(0u128, |acc, byte| (acc << 8) | u128::from(*byte)),
        };
        let value = (raw as u128) & ((1u128 << bitfield.bit_length) - 1);
        let merged = (storage & !mask) | (value << bitfield.bit_position);
        let bytes = merged.to_le_bytes();
        for index in 0..len {
            let byte = match bitfield.endian {
                Endian::Little => bytes[index],
                Endian::Big => bytes[len - 1 - index],
            };
            rebuilt[start + index] = byte;
        }
    }
    assert_eq!(
        rebuilt, oracle.bits_bytes,
        "bit-fields cover the probe bytes"
    );

    // Global objects carry the addresses the program printed. macOS slides a PIE
    // image at load time, so the comparison allows exactly one constant shift for
    // the whole document instead of one per symbol.
    let mut slide: Option<i128> = None;
    for (name, address) in &oracle.addresses {
        if name == "packet_callback" {
            continue; // published in `functions`, checked below
        }
        let entry = document["symbols"]
            .get(name)
            .unwrap_or_else(|| panic!("symbol {name} is missing"));
        let recorded = entry["address"].as_u64().unwrap_or_else(|| {
            panic!("symbol {name} has no address");
        });
        let offset = i128::from(*address) - i128::from(recorded);
        match slide {
            None => slide = Some(offset),
            Some(expected) => assert_eq!(
                offset, expected,
                "symbol {name} differs from the rest of the image"
            ),
        }
    }
    let callback_entry = &document["functions"]["packet_callback"];
    let callback = callback_entry["address"]
        .as_u64()
        .expect("callback address");
    let expected = i128::from(oracle.addresses["packet_callback"]) - slide.unwrap_or(0);
    assert_eq!(
        i128::from(callback),
        expected,
        "packet_callback shares the image shift"
    );
    assert_eq!(
        callback_entry["parameters"].as_array().map(Vec::len),
        Some(2)
    );
}

// ---------------------------------------------------------------------------
// Linux: gcc, gcc DWARF 5, clang, relocatable object, strip, compression
// ---------------------------------------------------------------------------

fn build_host_probe(directory: &Path, compiler: &Path, output: &str, extra: &[&str]) -> PathBuf {
    // Compile and link separately: `dsymutil` reads the debug map of the image and
    // pulls the DWARF out of the object files it names, so on macOS they have to
    // still exist.
    let object = directory.join(format!("{output}.o"));
    compile(
        Command::new(compiler)
            .args([
                "-O0",
                "-g",
                "-fno-eliminate-unused-debug-types",
                "-fno-pie",
                "-c",
            ])
            .args(extra)
            .arg(PROBE_C)
            .arg("-o")
            .arg(&object),
    );
    let binary = directory.join(output);
    compile(
        Command::new(compiler)
            .arg(&object)
            .arg("-no-pie")
            .arg("-o")
            .arg(&binary),
    );
    binary
}

#[cfg(unix)]
#[test]
fn gcc_dwarf4_matches_the_probe_oracle() {
    let Some(cc) = tool("cc") else { return };
    let directory = tempdir("gcc4");
    let binary = build_host_probe(&directory, &cc, "probe", &["-gdwarf-4"]);
    let oracle = Oracle::parse(&run_binary(&binary));
    let output = directory.join("probe.json");
    let result = convert_binary(&binary, &output);
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&output);
    assert_probe_layout(&document, &oracle, host_architecture());
    let typed = load_typed(&output);
    typed.validate().expect("converted document validates");
    // The reader and the writer agree byte for byte, and no host path leaks.
    assert_eq!(
        typed.to_vec().unwrap(),
        std::fs::read(&output).unwrap(),
        "deserialize then serialize reproduces the file"
    );
    let text = std::fs::read_to_string(&output).unwrap();
    let directory_text = directory.to_string_lossy();
    assert!(
        !text.contains(directory_text.as_ref()),
        "the document must not embed the input directory"
    );
}

fn host_architecture() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    }
}

#[cfg(target_os = "linux")]
#[test]
fn gcc_dwarf5_and_clang_agree_with_the_oracle() {
    let Some(cc) = tool("cc") else { return };
    let directory = tempdir("variants");
    let mut variants = vec![
        // DWARF 2 and 3 use `DW_AT_bit_offset` and block-form member locations.
        ("probe2", cc.clone(), vec!["-gdwarf-2"]),
        ("probe3", cc.clone(), vec!["-gdwarf-3"]),
        ("probe4", cc.clone(), vec!["-gdwarf-4"]),
        ("probe5", cc.clone(), vec!["-gdwarf-5"]),
    ];
    if let Some(clang) = tool("clang") {
        variants.push(("probe-clang", clang.clone(), vec!["-gdwarf-4"]));
        variants.push(("probe-clang5", clang, vec!["-gdwarf-5"]));
    }
    for (name, compiler, flags) in variants {
        let binary = build_host_probe(&directory, &compiler, name, &flags);
        // Each binary is its own oracle: addresses differ between builds.
        let oracle = Oracle::parse(&run_binary(&binary));
        let output = directory.join(format!("{name}.json"));
        let result = convert_binary(&binary, &output);
        assert!(result.success(), "{name}: {}", result.describe());
        let document = load_document(&output);
        assert_probe_layout(&document, &oracle, host_architecture());
    }
}

#[cfg(unix)]
#[test]
fn relocatable_object_needs_types_only() {
    let Some(cc) = tool("cc") else { return };
    let directory = tempdir("object");
    let object = directory.join("probe.o");
    let mut command = Command::new(&cc);
    command
        .args([
            "-O0",
            "-g",
            "-gdwarf-4",
            "-fno-eliminate-unused-debug-types",
            "-c",
        ])
        .arg(PROBE_C)
        .arg("-o")
        .arg(&object);
    compile(&mut command);

    let full = directory.join("full.json");
    let result = convert(&object, &full, &[]);
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(result.stderr.contains("UnlinkedImage"), "{}", result.stderr);
    assert!(!full.exists());

    let types = directory.join("types.json");
    let result = convert(&object, &types, &["--types-only"]);
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&types);
    let linked = directory.join("linked.json");
    let binary = build_host_probe(&directory, &cc, "probe", &["-gdwarf-4"]);
    assert!(convert_binary(&binary, &linked).success());
    let linked_document = load_document(&linked);
    assert_eq!(
        document["user_types"]["Packet"], linked_document["user_types"]["Packet"],
        "types from the object match the linked image"
    );
    assert_eq!(
        document["symbols"].as_object().map(|map| map.len()),
        Some(0)
    );
    assert_eq!(
        document["functions"].as_object().map(|map| map.len()),
        Some(0)
    );
}

#[cfg(unix)]
#[test]
fn stripped_binary_reports_no_debug_information() {
    let Some(cc) = tool("cc") else { return };
    let Some(strip) = tool_any(&["strip", "llvm-strip", "llvm-strip-18"]) else {
        return;
    };
    let directory = tempdir("strip");
    let binary = build_host_probe(&directory, &cc, "probe", &["-gdwarf-4"]);
    let stripped = directory.join("probe.stripped");
    std::fs::copy(&binary, &stripped).unwrap();
    compile(Command::new(strip).arg(&stripped));
    let output = directory.join("stripped.json");
    let result = convert(&stripped, &output, &[]);
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(result.stderr.contains("NoDebugInfo"), "{}", result.stderr);
    assert!(!output.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn compressed_debug_sections_still_convert() {
    let Some(cc) = tool("cc") else { return };
    let Some(objcopy) = tool_any(&["llvm-objcopy", "llvm-objcopy-18"]) else {
        return;
    };
    let directory = tempdir("compressed");
    let binary = build_host_probe(&directory, &cc, "probe", &["-gdwarf-4"]);
    let plain = directory.join("plain.json");
    assert!(convert(&binary, &plain, &[]).success());
    let compressed = directory.join("probe.compressed");
    std::fs::copy(&binary, &compressed).unwrap();
    compile(
        Command::new(objcopy)
            .arg("--compress-debug-sections=zlib")
            .arg(&compressed),
    );
    let packed = directory.join("compressed.json");
    let result = convert(&compressed, &packed, &[]);
    assert!(result.success(), "{}", result.describe());
    let a = load_document(&plain);
    let b = load_document(&packed);
    assert_eq!(a["user_types"], b["user_types"], "types are equivalent");
    assert_eq!(a["symbols"], b["symbols"], "symbols are equivalent");
}

#[cfg(target_os = "linux")]
#[cfg(unix)]
#[test]
fn separate_debug_file_is_verified() {
    let Some(cc) = tool("cc") else { return };
    let Some(objcopy) = tool_any(&["objcopy", "llvm-objcopy", "llvm-objcopy-18"]) else {
        return;
    };
    let directory = tempdir("separate");
    let binary = build_host_probe(&directory, &cc, "probe", &["-gdwarf-4", "-Wl,--build-id"]);
    let debug = directory.join("probe.debug");
    let stripped = directory.join("probe.stripped");
    std::fs::copy(&binary, &stripped).unwrap();
    compile(
        Command::new(&objcopy)
            .arg("--only-keep-debug")
            .arg(&binary)
            .arg(&debug),
    );
    compile(Command::new(&objcopy).arg("--strip-debug").arg(&stripped));

    let output = directory.join("separate.json");
    let result = convert(
        &stripped,
        &output,
        &["--debug-file", debug.to_str().unwrap()],
    );
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&output);
    assert_eq!(document["user_types"]["Packet"]["size"].as_u64(), Some(80));

    // A debug file from another build is rejected.
    let other = directory.join("other.debug");
    let other_binary = build_host_probe(&directory, &cc, "probe-other", &["-gdwarf-5"]);
    compile(
        Command::new(objcopy)
            .arg("--only-keep-debug")
            .arg(&other_binary)
            .arg(&other),
    );
    let mismatch = directory.join("mismatch.json");
    let result = convert(
        &stripped,
        &mismatch,
        &["--debug-file", other.to_str().unwrap()],
    );
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(
        result.stderr.contains("DebugFileMismatch"),
        "{}",
        result.stderr
    );
    assert!(!mismatch.exists());
}

#[cfg(target_os = "linux")]
#[cfg(unix)]
#[test]
fn split_dwarf_requires_its_companion() {
    let Some(cc) = tool("cc") else { return };
    let directory = tempdir("split");
    let binary = build_host_probe(
        &directory,
        &cc,
        "probe-split",
        &["-gdwarf-5", "-gsplit-dwarf"],
    );
    let output = directory.join("split.json");
    let result = convert(&binary, &output, &[]);
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(
        result.stderr.contains("MissingDebugCompanion"),
        "{}",
        result.stderr
    );
    assert!(result.stderr.contains(".dwo"), "{}", result.stderr);
}

#[cfg(unix)]
#[test]
fn cpp_virtual_base_becomes_opaque() {
    let Some(cxx) = tool("c++")
        .or_else(|| tool("g++"))
        .or_else(|| tool("clang++"))
    else {
        return;
    };
    let directory = tempdir("cpp");
    let object = directory.join("probe-cpp.o");
    compile(
        Command::new(&cxx)
            .args([
                "-O0",
                "-g",
                "-gdwarf-4",
                "-fno-eliminate-unused-debug-types",
                "-fno-pie",
                "-c",
            ])
            .arg(CPP_PROBE)
            .arg("-o")
            .arg(&object),
    );
    let binary = directory.join("probe-cpp");
    compile(
        Command::new(&cxx)
            .arg(&object)
            .arg("-no-pie")
            .arg("-o")
            .arg(&binary),
    );
    let output = directory.join("cpp.json");
    let result = convert_binary(&binary, &output);
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&output);

    let opaque = &document["base_types"]["DerivedVirtual"];
    assert_eq!(opaque["kind"], "opaque");
    assert!(opaque["size"].as_u64().unwrap_or(0) >= 8);
    let reason = opaque["unsupported_reason"].as_str().unwrap_or_default();
    assert!(reason.contains("virtual base"), "{reason}");
    assert!(
        document["symbols"]["derived_virtual_global"]["type"]["kind"] == "base",
        "in-edges point at the opaque unit"
    );
    assert_eq!(
        document["symbols"]["derived_virtual_global"]["type"]["name"],
        "DerivedVirtual"
    );

    // Non-virtual bases keep their real offset.
    let plain = &document["user_types"]["Plain"];
    let base = &plain["fields"]["__base_1"];
    assert_eq!(base["offset"].as_u64(), Some(0));
    assert_eq!(base["type"]["name"], "PlainBase");
    assert_eq!(plain["fields"]["q"]["offset"].as_u64(), Some(4));

    // A forward declaration that is defined later keeps its complete definition.
    let later = &document["user_types"]["Later"];
    assert_eq!(later["size"].as_u64(), Some(8), "{later}");
    assert_eq!(later["fields"]["extra"]["offset"].as_u64(), Some(4));
    assert_eq!(
        document["user_types"]["Holder"]["fields"]["later"]["type"]["subtype"]["name"],
        "Later"
    );

    // A forward declaration stays incomplete and may be pointed at.
    let forward = &document["user_types"]["Fwd"];
    assert_eq!(forward["incomplete"], Value::Bool(true));
    assert_eq!(
        document["user_types"]["Holder"]["fields"]["ptr"]["type"]["subtype"]["name"],
        "Fwd"
    );
}

// ---------------------------------------------------------------------------
// Big-endian bit-fields
// ---------------------------------------------------------------------------

fn symbol_bytes(path: &Path) -> (u64, Vec<u8>) {
    let data = std::fs::read(path).expect("read object");
    let file = object::File::parse(&data[..]).expect("parse object");
    let symbol = file
        .symbols()
        .find(|symbol| symbol.name() == Ok("bf"))
        .expect("symbol bf");
    let section = symbol.section_index().expect("section");
    let section = file.section_by_index(section).expect("section data");
    let data = section.data().expect("bytes");
    let start = usize::try_from(symbol.address()).expect("address");
    let end = (start + 4).min(data.len());
    (symbol.address(), data[start..end].to_vec())
}

#[test]
fn big_endian_bitfields_decode_to_the_initializer() {
    let Some(clang) = tool("clang") else { return };
    if !clang_has_target(&clang, "powerpc64") {
        eprintln!("skipping: this clang build has no powerpc64 target");
        return;
    }
    let directory = tempdir("bigendian");
    for (tag, standard) in [("dwarf4", "-gdwarf-4"), ("dwarf5", "-gdwarf-5")] {
        let object = directory.join(format!("bf-be-{tag}.o"));
        compile(
            Command::new(&clang)
                .args([
                    "--target=powerpc64-unknown-linux-gnu",
                    "-O0",
                    "-g",
                    standard,
                    "-c",
                ])
                .arg(BE_PROBE)
                .arg("-o")
                .arg(&object),
        );
        let (address, bytes) = symbol_bytes(&object);
        assert_eq!(address, 0, "the probe symbol starts its section");
        let output = directory.join(format!("bf-be-{tag}.json"));
        let result = convert(&object, &output, &["--types-only"]);
        assert!(result.success(), "{tag}: {}", result.describe());
        let document = load_document(&output);
        assert_eq!(
            document["metadata"]["sym2isf"]["target"]["endian"].as_str(),
            Some("big")
        );
        assert_eq!(
            document["metadata"]["sym2isf"]["target"]["architecture"].as_str(),
            Some("powerpc64")
        );
        assert_eq!(
            bitfield_of(&document, "Bf", "pad").decode(&bytes),
            5,
            "{tag}: pad"
        );
        assert_eq!(
            bitfield_of(&document, "Bf", "field").decode(&bytes),
            -3,
            "{tag}: field"
        );
        assert_eq!(
            bitfield_of(&document, "Bf", "tail").decode(&bytes),
            0xA5,
            "{tag}: tail"
        );
    }
}

// ---------------------------------------------------------------------------
// Mach-O: objects, fat containers, dSYM bundles
// ---------------------------------------------------------------------------

#[test]
fn macho_objects_and_fat_architectures() {
    let Some(clang) = tool("clang") else { return };
    let directory = tempdir("macho");
    let x86 = directory.join("bf-x86_64.o");
    let arm = directory.join("bf-arm64.o");
    compile(
        Command::new(&clang)
            .args([
                "--target=x86_64-apple-macos11",
                "-O0",
                "-g",
                "-gdwarf-4",
                "-c",
            ])
            .arg(BE_PROBE)
            .arg("-o")
            .arg(&x86),
    );
    compile(
        Command::new(&clang)
            .args([
                "--target=arm64-apple-macos11",
                "-O0",
                "-g",
                "-gdwarf-4",
                "-c",
            ])
            .arg(BE_PROBE)
            .arg("-o")
            .arg(&arm),
    );
    let plain = directory.join("macho.json");
    let result = convert(&x86, &plain, &["--types-only"]);
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&plain);
    assert_eq!(
        document["metadata"]["sym2isf"]["target"]["architecture"].as_str(),
        Some("x86_64")
    );
    assert_eq!(document["user_types"]["Bf"]["size"].as_u64(), Some(4));

    // A universal-binary check needs `llvm-lipo`; some LLVM distributions (the
    // Windows one) do not ship it, so its absence is reported, not fatal.
    let Some(lipo) = ["llvm-lipo", "llvm-lipo-18", "llvm-lipo.exe"]
        .iter()
        .find_map(|name| find_tool(name))
    else {
        eprintln!("skipping: llvm-lipo is not available, fat containers unchecked");
        return;
    };
    let fat = directory.join("bf-fat.o");
    compile(
        Command::new(lipo)
            .arg("-create")
            .arg(&x86)
            .arg(&arm)
            .arg("-output")
            .arg(&fat),
    );
    let ambiguous = directory.join("ambig.json");
    let result = convert(&fat, &ambiguous, &["--types-only"]);
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(
        result.stderr.contains("AmbiguousArchitecture"),
        "{}",
        result.stderr
    );
    assert!(result.stderr.contains("aarch64"), "{}", result.stderr);

    let selected = directory.join("fat-arm.json");
    let result = convert(
        &fat,
        &selected,
        &["--types-only", "--architecture", "aarch64"],
    );
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&selected);
    assert_eq!(
        document["metadata"]["sym2isf"]["target"]["architecture"].as_str(),
        Some("aarch64")
    );

    let unknown = directory.join("unknown.json");
    let result = convert(&fat, &unknown, &["--types-only", "--architecture", "mips"]);
    assert_eq!(result.status, Some(1));
    assert!(
        result.stderr.contains("UnknownArchitecture"),
        "{}",
        result.stderr
    );
}

#[test]
fn dsym_bundle_selection() {
    let Some(clang) = tool("clang") else { return };
    let directory = tempdir("dsym");
    let object = directory.join("bf.o");
    compile(
        Command::new(&clang)
            .args([
                "--target=x86_64-apple-macos11",
                "-O0",
                "-g",
                "-gdwarf-4",
                "-c",
            ])
            .arg(BE_PROBE)
            .arg("-o")
            .arg(&object),
    );
    // A bundle with exactly one DWARF file is usable without a UUID.
    let single = directory.join("single.dSYM");
    let dwarf = single.join("Contents").join("Resources").join("DWARF");
    std::fs::create_dir_all(&dwarf).unwrap();
    std::fs::copy(&object, dwarf.join("bf")).unwrap();
    let output = directory.join("dsym.json");
    let result = convert(
        &object,
        &output,
        &["--types-only", "--debug-file", single.to_str().unwrap()],
    );
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&output);
    assert_eq!(document["user_types"]["Bf"]["size"].as_u64(), Some(4));

    // Several candidates and no image UUID cannot be resolved.
    let multi = directory.join("multi.dSYM");
    let dwarf = multi.join("Contents").join("Resources").join("DWARF");
    std::fs::create_dir_all(&dwarf).unwrap();
    std::fs::copy(&object, dwarf.join("a")).unwrap();
    std::fs::copy(&object, dwarf.join("b")).unwrap();
    let ambiguous = directory.join("dsym-multi.json");
    let result = convert(
        &object,
        &ambiguous,
        &["--types-only", "--debug-file", multi.to_str().unwrap()],
    );
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(
        result.stderr.contains("DebugFileMismatch"),
        "{}",
        result.stderr
    );

    // On macOS the real dSYM path (dsymutil) must work as well.
    #[cfg(target_os = "macos")]
    {
        let Some(dsymutil) = tool_any(&["dsymutil"]) else {
            return;
        };
        let object = directory.join("probe.o");
        compile(
            Command::new(&clang)
                .args(["-O0", "-g", "-gdwarf-4", "-c"])
                .arg(PROBE_C)
                .arg("-o")
                .arg(&object),
        );
        let binary = directory.join("probe");
        compile(Command::new(&clang).arg(&object).arg("-o").arg(&binary));
        let bundle = directory.join("probe.dSYM");
        compile(Command::new(dsymutil).arg(&binary).arg("-o").arg(&bundle));
        let oracle = Oracle::parse(&run_binary(&binary));
        let output = directory.join("dsymutil.json");
        let result = convert(
            &binary,
            &output,
            &["--debug-file", bundle.to_str().unwrap()],
        );
        assert!(result.success(), "{}", result.describe());
        let document = load_document(&output);
        assert_eq!(document["user_types"]["Packet"]["size"].as_u64(), Some(80));
        let expected = oracle.offsets["Packed"]["value"];
        assert_eq!(
            field(&document, "Packed", "value")["offset"].as_u64(),
            Some(expected)
        );
        // The image is slid at run time, so compare the distance between two
        // globals, which the layout fixes.
        let packet = document["symbols"]["packet_global"]["address"]
            .as_u64()
            .expect("packet_global");
        let bits = document["symbols"]["bits_global"]["address"]
            .as_u64()
            .expect("bits_global");
        assert_eq!(
            i128::from(bits) - i128::from(packet),
            i128::from(oracle.addresses["bits_global"])
                - i128::from(oracle.addresses["packet_global"]),
            "global layout distance"
        );
    }
}

// ---------------------------------------------------------------------------
// Output contract with a real input
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn cli_output_contract_on_a_real_input() {
    let Some(cc) = tool("cc") else { return };
    let directory = tempdir("contract");
    let binary = build_host_probe(&directory, &cc, "probe", &["-gdwarf-4"]);
    let first = directory.join("first.json");
    let second = directory.join("second.json");
    assert!(convert_binary(&binary, &first).success());
    assert!(convert_binary(&binary, &second).success());
    let a = std::fs::read(&first).unwrap();
    let b = std::fs::read(&second).unwrap();
    assert_eq!(a, b, "repeated conversions are byte identical");

    let packed = directory.join("probe.json.xz");
    assert!(convert_binary(&binary, &packed).success());
    let mut decompressed = Vec::new();
    lzma_rs::xz_decompress(
        &mut std::io::Cursor::new(std::fs::read(&packed).unwrap()),
        &mut decompressed,
    )
    .expect("xz payload");
    assert_eq!(decompressed, a, "xz and json carry the same bytes");

    // An existing output is never overwritten.
    let error = convert_binary(&binary, &first);
    assert_eq!(error.status, Some(1), "{}", error.describe());
    assert!(error.stderr.contains("OutputExists"), "{}", error.stderr);
    assert_eq!(std::fs::read(&first).unwrap(), a);

    // A wrong suffix is reported, not guessed.
    let bad = directory.join("probe.txt");
    let error = convert_binary(&binary, &bad);
    assert_eq!(error.status, Some(1), "{}", error.describe());
    assert!(
        error.stderr.contains("UnsupportedOutput"),
        "{}",
        error.stderr
    );
    assert!(!bad.exists());

    // Missing parent directory is an I/O error, not a silent mkdir.
    let missing = directory.join("no-such-dir/probe.json");
    let error = convert_binary(&binary, &missing);
    assert_eq!(error.status, Some(1), "{}", error.describe());
    assert!(error.stderr.contains("Io"), "{}", error.stderr);
}

// ---------------------------------------------------------------------------
// PDB
// ---------------------------------------------------------------------------

/// Directory with `probe.pdb`, `probe.exe` and `oracle.json` produced elsewhere.
fn pdb_artifacts() -> Option<PathBuf> {
    let directory = match std::env::var_os("SYM2ISF_PDB_DIR") {
        Some(directory) => PathBuf::from(directory),
        None if native_required() => {
            panic!("SYM2ISF_NATIVE_TESTS=1 but SYM2ISF_PDB_DIR is not set")
        }
        None => {
            eprintln!("skipping: SYM2ISF_PDB_DIR is not set");
            return None;
        }
    };
    for name in ["probe.pdb", "probe.exe", "oracle.json"] {
        let path = directory.join(name);
        if !path.is_file() {
            if native_required() {
                panic!("SYM2ISF_PDB_DIR is set but {} is missing", path.display());
            }
            eprintln!("skipping: {} is missing", path.display());
            return None;
        }
    }
    Some(directory)
}

fn assert_pdb_document(document: &Value, oracle: &Oracle) {
    assert_target_metadata(document, "x86_64", oracle);
    assert_eq!(
        document["user_types"]["Packet"]["size"].as_u64(),
        Some(oracle.sizes["Packet"])
    );
    for (member, offset) in &oracle.offsets["Packet"] {
        assert_eq!(
            field_offset(document, "Packet", member),
            *offset,
            "offsetof(Packet.{member})"
        );
    }
    assert_eq!(
        field_offset(document, "Packed", "value"),
        oracle.offsets["Packed"]["value"]
    );
    assert_eq!(
        document["user_types"]["Node"]["size"].as_u64(),
        Some(oracle.sizes["Node"])
    );
    assert_eq!(
        field(document, "Node", "next")["type"]["subtype"]["name"],
        "Node"
    );
    let matrix = &field(document, "Packet", "matrix")["type"];
    assert_eq!(matrix["count"].as_u64(), Some(2));
    assert_eq!(matrix["subtype"]["count"].as_u64(), Some(3));
    assert_eq!(field(document, "Packet", "code")["type"]["kind"], "enum");
    assert_eq!(
        document["enums"]["SignedCode"]["constants"]["CODE_NEG"].as_i64(),
        Some(-3)
    );
    let callback = &field(document, "Packet", "callback")["type"];
    assert_eq!(callback["subtype"]["kind"], "function");
    assert_eq!(
        callback["subtype"]["parameters"].as_array().map(Vec::len),
        Some(2)
    );

    for (member, expected) in &oracle.bits_values {
        let raw = bitfield_of(document, "Bits", member).decode(&oracle.bits_bytes);
        assert_eq!(raw, i128::from(*expected), "bit-field {member}");
    }

    let base = document["metadata"]["sym2isf"]["image_base"]
        .as_u64()
        .expect("image base");
    for (name, address) in &oracle.addresses {
        if name == "packet_callback" {
            continue; // published in `functions`, checked below
        }
        let entry = document["symbols"]
            .get(name)
            .unwrap_or_else(|| panic!("symbol {name} missing"));
        assert_eq!(
            entry["address"].as_u64(),
            Some(*address),
            "address of {name}"
        );
        assert!(*address >= base);
    }
    assert_eq!(
        document["functions"]["packet_callback"]["address"].as_u64(),
        Some(oracle.addresses["packet_callback"])
    );
}

#[test]
fn pdb_from_the_windows_artifact_job() {
    let Some(directory) = pdb_artifacts() else {
        return;
    };
    let oracle = {
        let text = std::fs::read_to_string(directory.join("oracle.json")).expect("oracle");
        Oracle::parse(&text)
    };
    let output = directory.join("artifact.json");
    if output.exists() {
        std::fs::remove_file(&output).unwrap();
    }
    let result = convert_pdb(
        &directory.join("probe.pdb"),
        &output,
        &["--image", directory.join("probe.exe").to_str().unwrap()],
    );
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&output);
    assert_pdb_document(&document, &oracle);

    // Two runs produce the same bytes, and the document survives a round trip.
    let repeat = directory.join("artifact-repeat.json");
    if repeat.exists() {
        std::fs::remove_file(&repeat).unwrap();
    }
    let again = convert_pdb(
        &directory.join("probe.pdb"),
        &repeat,
        &["--image", directory.join("probe.exe").to_str().unwrap()],
    );
    assert!(again.success(), "{}", again.describe());
    let first_bytes = std::fs::read(&output).unwrap();
    assert_eq!(
        std::fs::read(&repeat).unwrap(),
        first_bytes,
        "repeated PDB conversion is byte identical"
    );
    let typed = load_typed(&output);
    typed.validate().expect("PDB document validates");
    assert_eq!(
        typed.to_vec().unwrap(),
        first_bytes,
        "deserialize then serialize reproduces the PDB document"
    );
    let text = String::from_utf8_lossy(&first_bytes);
    assert!(
        !text.contains(&directory.to_string_lossy().to_string()),
        "the PDB document must not embed its own path"
    );

    // types-only skips addresses and symbol tables.
    let types = directory.join("artifact-types.json");
    if types.exists() {
        std::fs::remove_file(&types).unwrap();
    }
    let result = convert_pdb(&directory.join("probe.pdb"), &types, &["--types-only"]);
    assert!(result.success(), "{}", result.describe());
    let types_document = load_document(&types);
    assert_eq!(
        types_document["symbols"].as_object().map(|map| map.len()),
        Some(0)
    );
    assert_eq!(
        types_document["functions"].as_object().map(|map| map.len()),
        Some(0)
    );
    assert_eq!(
        types_document["user_types"]["Packet"]["size"].as_u64(),
        Some(oracle.sizes["Packet"])
    );
}

#[test]
fn pdb_error_paths() {
    let Some(directory) = pdb_artifacts() else {
        return;
    };
    let pdb = directory.join("probe.pdb");
    let exe = directory.join("probe.exe");

    // A PDB-only conversion needs an explicit image base.
    let missing = directory.join("missing-base.json");
    if missing.exists() {
        std::fs::remove_file(&missing).unwrap();
    }
    let result = convert_pdb(&pdb, &missing, &[]);
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(
        result.stderr.contains("MissingImageBase"),
        "{}",
        result.stderr
    );
    assert!(!missing.exists());

    // An explicit base works without the image.
    let explicit = directory.join("explicit-base.json");
    if explicit.exists() {
        std::fs::remove_file(&explicit).unwrap();
    }
    let result = convert_pdb(&pdb, &explicit, &["--image-base", "0x10000000"]);
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&explicit);
    assert_eq!(
        document["metadata"]["sym2isf"]["image_base"].as_u64(),
        Some(0x1000_0000)
    );

    // A different image is rejected by GUID.
    let other = directory.join("other.exe");
    let mut patched = std::fs::read(&exe).unwrap();
    let signature = patched
        .windows(4)
        .position(|window| window == b"RSDS")
        .expect("CodeView signature");
    patched[signature + 4] ^= 0xff;
    std::fs::write(&other, &patched).unwrap();
    let mismatch = directory.join("mismatch.json");
    if mismatch.exists() {
        std::fs::remove_file(&mismatch).unwrap();
    }
    let result = convert_pdb(&pdb, &mismatch, &["--image", other.to_str().unwrap()]);
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(
        result.stderr.contains("DebugFileMismatch"),
        "{}",
        result.stderr
    );
    assert!(!mismatch.exists());
}

/// Locally linkable PDB: needs clang plus `lld-link` (or MSVC's `link`).
#[test]
fn pdb_local_link_is_consistent_with_dwarf() {
    if pdb_artifacts().is_some() {
        return; // covered by the artifact job
    }
    let Some(clang) = find_tool("clang").or_else(|| find_tool("clang.exe")) else {
        eprintln!("skipping: clang is not available");
        return;
    };
    #[cfg(windows)]
    let linkers: Vec<&str> = vec!["lld-link", "lld-link-18", "link"];
    #[cfg(not(windows))]
    // `link` is only a linker on Windows; on Unix it is coreutils' hard-link tool.
    let linkers: Vec<&str> = vec!["lld-link", "lld-link-18"];
    let Some(linker) = linkers.iter().find_map(|name| find_tool(name)) else {
        eprintln!("skipping: no linker that writes PDB files is available");
        return;
    };
    let directory = tempdir("pdb");
    let object = directory.join("pdb_probe.obj");
    compile(
        Command::new(&clang)
            .args([
                "--target=x86_64-pc-windows-msvc",
                "-O1",
                "-g",
                "-gcodeview",
                "-c",
            ])
            .arg("-I")
            .arg(PROBE_HEADER_DIR)
            .arg(PDB_PROBE_C)
            .arg("-o")
            .arg(&object),
    );
    let exe = directory.join("probe.exe");
    let pdb = directory.join("probe.pdb");
    compile(
        Command::new(&linker)
            .args([
                "/nologo",
                "/debug",
                "/machine:x64",
                "/entry:main",
                "/subsystem:console",
                "/nodefaultlib",
                "/base:0x140000000",
            ])
            .arg(format!("/out:{}", exe.display()))
            .arg(format!("/pdb:{}", pdb.display()))
            .arg(&object),
    );

    let output = directory.join("pdb.json");
    let result = convert_pdb(&pdb, &output, &["--image", exe.to_str().unwrap()]);
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&output);

    // Layout must agree with the DWARF conversion of the same header on this host.
    #[cfg(unix)]
    {
        let cc = tool_any(&["cc", "clang"]);
        if let Some(cc) = cc {
            compile(
                Command::new(&cc)
                    .args(["-O0", "-g", "-gdwarf-4", "-Itests/fixtures", "-c"])
                    .arg(PDB_PROBE_C)
                    .arg("-o")
                    .arg(directory.join("pdb_probe.o")),
            );
            let dwarf_types = directory.join("dwarf-types.json");
            let result = convert(
                &directory.join("pdb_probe.o"),
                &dwarf_types,
                &["--types-only"],
            );
            assert!(result.success(), "{}", result.describe());
            let dwarf_document = load_document(&dwarf_types);
            for aggregate in ["Packet", "Node", "Value", "Packed", "Bits"] {
                assert_eq!(
                    document["user_types"][aggregate]["size"],
                    dwarf_document["user_types"][aggregate]["size"],
                    "sizeof({aggregate}) agrees between PDB and DWARF"
                );
                let pdb_fields = document["user_types"][aggregate]["fields"]
                    .as_object()
                    .expect("fields");
                let dwarf_fields = dwarf_document["user_types"][aggregate]["fields"]
                    .as_object()
                    .expect("fields");
                for (name, entry) in pdb_fields {
                    assert_eq!(
                        entry["offset"], dwarf_fields[name]["offset"],
                        "offsetof({aggregate}.{name})"
                    );
                }
            }
        }
    }

    // Addresses must point at the real objects inside the image.
    let image = std::fs::read(&exe).unwrap();
    let parsed = object::File::parse(&image[..]).expect("PE");
    let base = parsed.relative_address_base();
    assert_eq!(
        document["metadata"]["sym2isf"]["image_base"].as_u64(),
        Some(base)
    );
    for (name, expected) in [
        ("packed_global", &[0x5au8, 0xef, 0xbe, 0xad, 0xde][..]),
        ("value_global", &[0x44u8, 0x33, 0x22, 0x11][..]),
    ] {
        let address = document["symbols"][name]["address"]
            .as_u64()
            .expect("address");
        assert!(address >= base);
        let mut found = None;
        for section in parsed.sections() {
            let start = section.address();
            let data = section.data().unwrap_or_default();
            if address >= start && address < start + data.len() as u64 {
                let offset = usize::try_from(address - start).expect("offset");
                found = data
                    .get(offset..offset + expected.len())
                    .map(|slice| slice.to_vec());
            }
        }
        assert_eq!(found.as_deref(), Some(expected), "bytes of {name}");
    }
}

// ---------------------------------------------------------------------------
// Windows: cl plus the produced PDB
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[test]
fn cl_and_its_pdb_match_the_probe_oracle() {
    let Some(cl) = tool_any(&["cl", "cl.exe"]) else {
        return;
    };
    let directory = tempdir("cl");
    let exe = directory.join("probe.exe");
    let pdb = directory.join("probe.pdb");
    compile(
        Command::new(&cl)
            .args(["/nologo", "/Zi", "/Od"])
            .arg(format!("/Fd:{}", directory.join("compile.pdb").display()))
            .arg(format!("/Fe:{}", exe.display()))
            .arg(format!("/I{PROBE_HEADER_DIR}"))
            .arg(PROBE_C)
            .arg("/link")
            .args([
                "/DEBUG:FULL",
                "/INCREMENTAL:NO",
                "/DYNAMICBASE:NO",
                "/BASE:0x140000000",
            ])
            .arg(format!("/PDB:{}", pdb.display())),
    );
    let oracle = Oracle::parse(&run_binary(&exe));
    let output = directory.join("probe.json");
    let result = convert_pdb(&pdb, &output, &["--image", exe.to_str().unwrap()]);
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&output);
    assert_pdb_document(&document, &oracle);

    // Only a PDB plus an explicit base is enough as well.
    let explicit = directory.join("explicit.json");
    let result = convert_pdb(&pdb, &explicit, &["--image-base", "0x140000000"]);
    assert!(result.success(), "{}", result.describe());
    let explicit_document = load_document(&explicit);
    assert_eq!(
        explicit_document["symbols"]["packet_global"]["address"],
        document["symbols"]["packet_global"]["address"],
        "the explicit base reproduces the image base"
    );
}

// ---------------------------------------------------------------------------
// 32-bit Linux target
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn thirty_two_bit_target_layout() {
    let Some(cc) = tool("cc") else { return };
    let directory = tempdir("i386");
    let object = directory.join("probe32.o");
    // Emitting 32-bit code needs the multilib runtime (gcc-multilib in CI); a host
    // without it reports the gap instead of failing a target it cannot build.
    let compiled = Command::new(&cc)
        .args([
            "-m32",
            "-O0",
            "-g",
            "-gdwarf-4",
            "-fno-pie",
            "-fno-eliminate-unused-debug-types",
            "-c",
        ])
        .arg(PROBE_C)
        .arg("-o")
        .arg(&object)
        .output();
    match compiled {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            eprintln!(
                "skipping 32-bit target: cc -m32 failed ({})",
                String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .next()
                    .unwrap_or("")
            );
            return;
        }
        Err(error) => {
            eprintln!("skipping 32-bit target: {error}");
            return;
        }
    }
    let binary = directory.join("probe32");
    compile(
        Command::new(&cc)
            .arg(&object)
            .args(["-m32", "-no-pie"])
            .arg("-o")
            .arg(&binary),
    );
    let oracle = Oracle::parse(&run_binary(&binary));
    assert_eq!(oracle.pointer_size, 4, "the fixture must be 32-bit");
    let output = directory.join("probe32.json");
    let result = convert_binary(&binary, &output);
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&output);
    assert_eq!(
        document["metadata"]["sym2isf"]["target"]["pointer_size"].as_u64(),
        Some(4)
    );
    assert_probe_layout(&document, &oracle, "i386");
}

// ---------------------------------------------------------------------------
// Relocations in a partially linked object
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn merged_units_apply_relocations() {
    let Some(cc) = tool("cc") else { return };
    let directory = tempdir("reloc");
    let first = directory.join("a.c");
    let second = directory.join("b.c");
    std::fs::write(
        &first,
        "struct A { int values[7]; };\nstruct A a_global;\nint a_function(struct A *value) { return value->values[0]; }\n",
    )
    .unwrap();
    std::fs::write(
        &second,
        "struct B { char text[13]; };\nstruct B b_global;\nint b_function(struct B *value) { return value->text[0]; }\n",
    )
    .unwrap();
    let mut objects = Vec::new();
    for source in [&first, &second] {
        let object = source.with_extension("o");
        compile(
            Command::new(&cc)
                .args([
                    "-O0",
                    "-g",
                    "-gdwarf-4",
                    "-fno-eliminate-unused-debug-types",
                    "-c",
                ])
                .arg(source)
                .arg("-o")
                .arg(&object),
        );
        objects.push(object);
    }
    // A partially linked object keeps two units in one `.debug_info`, so every
    // type and string reference needs its relocation applied.
    let merged = directory.join("merged.o");
    compile(
        Command::new(&cc)
            .arg("-r")
            .args(&objects)
            .arg("-o")
            .arg(&merged),
    );
    let output = directory.join("merged.json");
    let result = convert(&merged, &output, &["--types-only"]);
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&output);
    assert_eq!(
        document["user_types"]["A"]["size"].as_u64(),
        Some(28),
        "first unit resolved: {document}"
    );
    assert_eq!(document["user_types"]["B"]["size"].as_u64(), Some(13));
    // Relocated string references give both units their own type names.
    assert_eq!(
        document["user_types"]["B"]["fields"]["text"]["type"]["name"]
            .as_str()
            .unwrap_or("char"),
        "char"
    );
}

// ---------------------------------------------------------------------------
// Layouts that cannot be represented statically
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn dynamic_arrays_are_rejected_with_their_record() {
    let Some(cc) = tool("cc") else { return };
    let directory = tempdir("vla");
    let source = directory.join("vla.c");
    std::fs::write(
        &source,
        "struct Holder { int fixed; };\n\
         int sum(int n)\n{\n    int dynamic[n];\n    for (int i = 0; i < n; i++) { dynamic[i] = i; }\n    return dynamic[0] + dynamic[n - 1];\n}\n\
         struct Holder holder_global;\n\
         int main(void) { return sum(4) + holder_global.fixed; }\n",
    )
    .unwrap();
    let object = directory.join("vla.o");
    compile(
        Command::new(&cc)
            .args(["-O0", "-g", "-gdwarf-4", "-fno-pie", "-c"])
            .arg(&source)
            .arg("-o")
            .arg(&object),
    );
    let binary = directory.join("vla");
    compile(
        Command::new(&cc)
            .arg(&object)
            .arg("-no-pie")
            .arg("-o")
            .arg(&binary),
    );
    let output = directory.join("vla.json");
    let result = convert_binary(&binary, &output);
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(
        result.stderr.contains("UnsupportedLayout"),
        "{}",
        result.stderr
    );
    assert!(
        result.stderr.contains(".debug_info DIE at 0x"),
        "the failing DIE is named: {}",
        result.stderr
    );
    assert!(!output.exists(), "nothing is written for a rejected layout");
}

// ---------------------------------------------------------------------------
// The compilation unit is the name domain
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn compilation_unit_is_the_name_domain() {
    let Some(cc) = tool("cc") else { return };
    let directory = tempdir("cu-domain");
    let sources = [
        (
            "aa.c",
            "static struct Local { int a; } local_a = {1};\nstruct Local *point_a(void) { return &local_a; }\n",
        ),
        (
            "bb.c",
            "static struct Local { char b; long c; } local_b = {2, 3};\nstruct Local *point_b(void) { return &local_b; }\n",
        ),
        (
            "main.c",
            "struct Local;\nstruct Local *point_a(void);\nstruct Local *point_b(void);\nint main(void) { return point_a() != 0 && point_b() != 0; }\n",
        ),
    ];
    let mut objects = Vec::new();
    for (name, source) in sources {
        let source_path = directory.join(name);
        std::fs::write(&source_path, source).unwrap();
        let object = source_path.with_extension("o");
        compile(
            Command::new(&cc)
                .args(["-O0", "-g", "-gdwarf-4", "-c"])
                .arg(&source_path)
                .arg("-o")
                .arg(&object),
        );
        objects.push(object);
    }
    let binary = directory.join("probe");
    compile(Command::new(&cc).args(&objects).arg("-o").arg(&binary));
    let output = directory.join("probe.json");
    let result = convert_binary(&binary, &output);
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&output);

    // Three compilation units define `struct Local`; each keeps its own entry and
    // the unit names the variant.
    let mut sizes = BTreeMap::new();
    for (name, entry) in document["user_types"].as_object().expect("user types") {
        if name.starts_with("Local") {
            sizes.insert(name.clone(), entry["size"].as_u64().unwrap_or(999));
        }
    }
    assert_eq!(sizes.len(), 3, "{sizes:?}");
    assert_eq!(sizes.get("Local"), Some(&4), "{sizes:?}");
    assert_eq!(sizes.get("Local@bb.c"), Some(&16), "{sizes:?}");
    assert_eq!(
        document["user_types"]["Local@main.c"]["incomplete"],
        Value::Bool(true),
        "the forward declaration in a third unit is its own entry"
    );
}

#[test]
fn pdb_keeps_translation_unit_types_apart() {
    // Clang + lld share the forward-reference record of `Local` between the two
    // units, so the units cannot be told apart from the symbols; both complete
    // layouts must still reach the document as separate types.
    let Some(clang) = find_tool("clang") else {
        return;
    };
    #[cfg(windows)]
    let linkers: Vec<&str> = vec!["lld-link", "lld-link-18", "link"];
    #[cfg(not(windows))]
    let linkers: Vec<&str> = vec!["lld-link", "lld-link-18"];
    let Some(linker) = linkers.iter().find_map(|name| find_tool(name)) else {
        eprintln!("skipping: no linker that writes PDB files is available");
        return;
    };
    let directory = tempdir("pdb-domain");
    let mut objects = Vec::new();
    for (name, source) in [
        (
            "tu_one.c",
            "static volatile struct Local { int a; } local_one = {1};\nint read_one(void) { return local_one.a; }\n",
        ),
        (
            "tu_two.c",
            "static volatile struct Local { char b; long long c; } local_two = {2, 3};\nint read_two(void) { return local_two.b + (int)local_two.c; }\n",
        ),
    ] {
        let source_path = directory.join(name);
        std::fs::write(&source_path, source).unwrap();
        let object = source_path.with_extension("obj");
        compile(
            Command::new(&clang)
                .args([
                    "--target=x86_64-pc-windows-msvc",
                    "-O0",
                    "-g",
                    "-gcodeview",
                    "-fno-eliminate-unused-debug-types",
                    "-c",
                ])
                .arg(&source_path)
                .arg("-o")
                .arg(&object),
        );
        objects.push(object);
    }
    let exe = directory.join("probe.exe");
    let pdb = directory.join("probe.pdb");
    compile(
        Command::new(&linker)
            .args([
                "/nologo",
                "/debug",
                "/machine:x64",
                "/entry:read_one",
                "/subsystem:console",
                "/nodefaultlib",
                "/base:0x140000000",
            ])
            .arg(format!("/out:{}", exe.display()))
            .arg(format!("/pdb:{}", pdb.display()))
            .args(&objects),
    );

    let output = directory.join("probe.json");
    let result = convert_pdb(&pdb, &output, &["--types-only"]);
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&output);
    let mut complete = BTreeMap::new();
    for (name, entry) in document["user_types"].as_object().expect("user types") {
        if !name.starts_with("Local") || entry["size"].as_u64() == Some(0) {
            continue;
        }
        complete.insert(name.clone(), entry["size"].as_u64().unwrap_or(999));
    }
    assert_eq!(complete.len(), 2, "{complete:?}");
    assert!(complete.values().any(|size| *size == 4), "{complete:?}");
    assert!(complete.values().any(|size| *size == 16), "{complete:?}");
    assert!(
        complete
            .keys()
            .any(|name| name.contains('@') || name.contains("__pdb_")),
        "one variant is disambiguated: {complete:?}"
    );
}

// ---------------------------------------------------------------------------
// Windows: the compilation unit names a same-named type
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[test]
fn cl_names_a_type_by_its_translation_unit() {
    let Some(cl) = tool_any(&["cl", "cl.exe"]) else {
        return;
    };
    let directory = tempdir("cl-domain");
    let mut objects = Vec::new();
    for (name, source) in [
        (
            "tu_one.c",
            "static struct Local { int a; } local_one = {1};\nint read_one(void) { return local_one.a; }\n",
        ),
        (
            "tu_two.c",
            "static struct Local { char b; long long c; } local_two = {2, 3};\nint read_two(void) { return local_two.b + (int)local_two.c; }\n",
        ),
    ] {
        let source_path = directory.join(name);
        std::fs::write(&source_path, source).unwrap();
        let object = source_path.with_extension("obj");
        compile(
            Command::new(&cl)
                .args(["/nologo", "/Zi", "/Od", "/c"])
                .arg(format!("/Fd{}", directory.join("compile.pdb").display()))
                .arg(&source_path)
                .arg(format!("/Fo{}", object.display())),
        );
        objects.push(object);
    }
    let exe = directory.join("probe.exe");
    let pdb = directory.join("probe.pdb");
    compile(
        Command::new(&cl)
            .args(["/nologo", "/Zi", "/Od"])
            .arg(format!("/Fd{}", directory.join("compile.pdb").display()))
            .arg(format!("/Fe:{}", exe.display()))
            .args(&objects)
            .args([
                "/link",
                "/DEBUG:FULL",
                "/INCREMENTAL:NO",
                "/DYNAMICBASE:NO",
                "/entry:read_one",
                "/subsystem:console",
                "/nodefaultlib",
            ])
            .arg("/BASE:0x140000000")
            .arg(format!("/PDB:{}", pdb.display())),
    );
    let output = directory.join("probe.json");
    let result = convert_pdb(&pdb, &output, &["--types-only"]);
    assert!(result.success(), "{}", result.describe());
    let document = load_document(&output);
    let names: Vec<(&String, u64)> = document["user_types"]
        .as_object()
        .expect("user types")
        .iter()
        .filter(|(name, _)| name.starts_with("Local"))
        .map(|(name, entry)| (name, entry["size"].as_u64().unwrap_or(999)))
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    let mut sizes: Vec<u64> = names.iter().map(|(_, size)| *size).collect();
    sizes.sort_unstable();
    assert_eq!(sizes, vec![4, 16], "{names:?}");
    let suffixed: Vec<&(&String, u64)> = names
        .iter()
        .filter(|(name, _)| name.contains('@'))
        .collect();
    assert_eq!(suffixed.len(), 1, "one variant carries its unit: {names:?}");
    assert!(
        suffixed[0].0.ends_with("@tu_one.obj") || suffixed[0].0.ends_with("@tu_two.obj"),
        "the suffix is the unit that defined it: {names:?}"
    );
}

// ---------------------------------------------------------------------------
// PDB types as C declarations, accepted and executed by a real TCC
// ---------------------------------------------------------------------------

fn c_source(
    subcommand: &str,
    input: &Path,
    roots: &[&str],
    output: &Path,
    tcc: &Path,
) -> CliOutput {
    let mut args: Vec<std::ffi::OsString> = vec![subcommand.into(), input.as_os_str().to_owned()];
    for root in roots {
        args.push("--type".into());
        args.push((*root).into());
    }
    args.push("--output".into());
    args.push(output.as_os_str().to_owned());
    args.push("--tcc".into());
    args.push(tcc.as_os_str().to_owned());
    cli(args)
}

/// Run one C command with arbitrary selection arguments.
fn c_args(subcommand: &str, input: &Path, args: &[&OsStr], output: &Path, tcc: &Path) -> CliOutput {
    let mut argv: Vec<std::ffi::OsString> = vec![subcommand.into(), input.as_os_str().to_owned()];
    argv.extend(args.iter().map(|value| value.to_os_string()));
    argv.push("--output".into());
    argv.push(output.as_os_str().to_owned());
    argv.push("--tcc".into());
    argv.push(tcc.as_os_str().to_owned());
    cli(argv)
}

/// Compile one translation unit with TCC and return the global symbols it exports.
#[cfg(target_os = "linux")]
fn global_symbols(tcc: &Path, nm: &Path, directory: &Path, source: &str, tag: &str) -> Vec<String> {
    let path = directory.join(format!("{tag}.c"));
    std::fs::write(&path, source).expect("source");
    let object = directory.join(format!("{tag}.o"));
    let compiled = Command::new(tcc)
        .args(["-Werror", "-c"])
        .arg(&path)
        .arg("-o")
        .arg(&object)
        .current_dir(directory)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", tcc.display()));
    assert!(
        compiled.status.success(),
        "tcc rejected the unit: {}
{}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
    let listed = Command::new(nm)
        .arg("-g")
        .arg(&object)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", nm.display()));
    assert!(listed.status.success(), "nm failed on {}", object.display());
    String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.ends_with(':'))
        .map(str::to_string)
        .collect()
}

/// Compile one translation unit with TCC without linking it.
#[cfg(target_os = "linux")]
fn tcc_compile_only(tcc: &Path, directory: &Path, source: &str, tag: &str) {
    let path = directory.join(format!("{tag}.c"));
    std::fs::write(&path, source).expect("source");
    let object = directory.join(format!("{tag}.o"));
    let compiled = Command::new(tcc)
        .args(["-Werror", "-c"])
        .arg(&path)
        .arg("-o")
        .arg(&object)
        .current_dir(directory)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", tcc.display()));
    assert!(
        compiled.status.success(),
        "tcc rejected {tag}: {}\n{}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
}

/// Compile and run a consumer translation unit with TCC, returning stdout.
#[cfg(target_os = "linux")]
fn tcc_run(tcc: &Path, directory: &Path, source: &str) -> String {
    let path = directory.join("consumer.c");
    std::fs::write(&path, source).expect("consumer source");
    let output = Command::new(tcc)
        .args(["-Werror", "-run"])
        .arg(&path)
        .current_dir(directory)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", tcc.display()));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "consumer failed with {}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

/// Consumer that checks the generated declarations against a real layout oracle.
///
/// Both frontends feed this same program: the fixture, the oracle and therefore
/// the expected bytes are identical, so a DWARF and a PDB document must describe
/// the same memory.
#[cfg(target_os = "linux")]
fn layout_consumer(oracle: &Oracle) -> String {
    let matrix_last = oracle.offsets["Packet"]["matrix"] + (3 + 2) * 2;
    let nodes_value =
        oracle.offsets["Packet"]["nodes"] + oracle.sizes["Node"] + oracle.offsets["Node"]["value"];
    let bits_bytes: String = oracle
        .bits_bytes
        .iter()
        .map(|byte| format!("0x{byte:02x}, "))
        .collect();
    format!(
        r#"
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(condition) do {{ if (!(condition)) {{ printf("failed: %s\n", #condition); failures = 1; }} }} while (0)

int main(void)
{{
    s2c_s_Packed packed;
    memset(&packed, 0, sizeof packed);
    packed.tag = 0x5a;
    packed.value = 0xdeadbeefu;
    CHECK(sizeof packed == {packed_size});
    CHECK(offsetof(s2c_s_Packed, tag) == {packed_tag});
    CHECK(offsetof(s2c_s_Packed, value) == {packed_value});
    {{
        const unsigned char expected[5] = {{0x5a, 0xef, 0xbe, 0xad, 0xde}};
        CHECK(memcmp(&packed, expected, 5) == 0);
    }}

    s2c_s_Node node;
    memset(&node, 0, sizeof node);
    node.value = 0x11223344;
    node.next = &node;
    CHECK(node.next == &node);
    CHECK(node.value == 0x11223344);
    CHECK(sizeof(s2c_s_Node) == {node_size});
    CHECK(offsetof(s2c_s_Node, next) == {node_next});

    s2c_s_Packet packet;
    memset(&packet, 0, sizeof packet);
    packet.next = &packet;
    CHECK(packet.next == &packet);
    packet.nodes[1].next = &node;
    packet.nodes[1].value = 1234567;
    CHECK(packet.nodes[0].next == 0);
    CHECK(packet.nodes[1].next == &node);
    CHECK(packet.nodes[1].value == 1234567);
    CHECK(offsetof(s2c_s_Packet, nodes) == {packet_nodes});
    CHECK(offsetof(s2c_s_Packet, nodes[1].value) == {nodes_value});
    packet.payload.word = 0xfeedfaceu;
    CHECK(packet.payload.word == 0xfeedfaceu);
    packet.payload.bytes[0] = 0x11;
    CHECK(packet.payload.word == 0xfeedfa11u);
    packet.matrix[1][2] = 0x55aau;
    CHECK(packet.matrix[1][2] == 0x55aau);
    CHECK(offsetof(s2c_s_Packet, matrix[1][2]) == {matrix_last});
    CHECK(offsetof(s2c_s_Packet, code) == {packet_code});
    CHECK(offsetof(s2c_s_Packet, callback) == {packet_callback});
    CHECK(packet.code == 0);
    packet.code = s2c_e_SignedCode_CODE__NEG;
    CHECK(packet.code == -3);
    packet.callback = 0;
    CHECK(packet.callback == 0);
    CHECK(sizeof(s2c_s_Packet) == {packet_size});
    CHECK(sizeof(s2c_u_Value) == {value_size});

    s2c_s_Bits bits;
    memset(&bits, 0, sizeof bits);
    s2c_s_Bits_set_pad(&bits, {bits_pad});
    s2c_s_Bits_set_field(&bits, {bits_field});
    s2c_s_Bits_set_tail(&bits, {bits_tail});
    CHECK(s2c_s_Bits_get_pad(&bits) == {bits_pad});
    CHECK(s2c_s_Bits_get_field(&bits) == {bits_field});
    CHECK(s2c_s_Bits_get_tail(&bits) == {bits_tail});
    CHECK(sizeof(s2c_s_Bits) == {bits_size});
    {{
        const unsigned char expected[{bits_length}] = {{{bits_bytes}}};
        CHECK(memcmp(&bits, expected, sizeof bits) == 0);
    }}
    {{
        unsigned char before[4];
        memcpy(before, &bits, sizeof bits);
        s2c_s_Bits_set_field(&bits, 7);
        CHECK(s2c_s_Bits_get_field(&bits) == 7);
        CHECK(s2c_s_Bits_get_pad(&bits) == {bits_pad});
        CHECK(s2c_s_Bits_get_tail(&bits) == {bits_tail});
        CHECK((((const unsigned char *)&bits)[0] & 0x07) == ({bits_pad} & 0x07));
        CHECK(((const unsigned char *)&bits)[1] == before[1]);
        CHECK(((const unsigned char *)&bits)[2] == 0);
        CHECK(((const unsigned char *)&bits)[3] == 0);
    }}

    printf("%s\n", failures ? "layout-failed" : "layout-ok");
    return failures;
}}
"#,
        packed_size = oracle.sizes["Packed"],
        packed_tag = oracle.offsets["Packed"]["tag"],
        packed_value = oracle.offsets["Packed"]["value"],
        node_size = oracle.sizes["Node"],
        node_next = oracle.offsets["Node"]["next"],
        packet_size = oracle.sizes["Packet"],
        packet_nodes = oracle.offsets["Packet"]["nodes"],
        packet_code = oracle.offsets["Packet"]["code"],
        packet_callback = oracle.offsets["Packet"]["callback"],
        nodes_value = nodes_value,
        matrix_last = matrix_last,
        value_size = oracle.sizes["Value"],
        bits_size = oracle.sizes["Bits"],
        bits_pad = oracle.bits_values["pad"],
        bits_field = oracle.bits_values["field"],
        bits_tail = oracle.bits_values["tail"],
        bits_bytes = bits_bytes,
        bits_length = oracle.bits_bytes.len(),
    )
}

#[cfg(target_os = "linux")]
#[test]
fn pdb_c_tcc_round_trip() {
    let Some(directory) = pdb_artifacts() else {
        return;
    };
    let Some(tcc) = tool("tcc") else { return };
    let oracle = {
        let text = std::fs::read_to_string(directory.join("oracle.json")).expect("oracle");
        Oracle::parse(&text)
    };
    let pdb = directory.join("probe.pdb");
    // Generated sources, sentinels and the consumer stay in a private directory:
    // the artifact directory only hosts the probe and its oracle.
    let scratch = tempdir("pdb-c");

    let source_path = scratch.join("layout.c");
    let result = c_source(
        "pdb-c",
        &pdb,
        &["Packet", "Packed", "Bits"],
        &source_path,
        &tcc,
    );
    assert!(result.success(), "{}", result.describe());
    assert!(
        result.stdout.is_empty(),
        "stdout stays empty: {}",
        result.describe()
    );
    assert!(
        result.stderr.contains("TCC-checked C source"),
        "{}",
        result.stderr
    );
    let source = std::fs::read_to_string(&source_path).expect("generated source");
    assert!(
        source.ends_with('\n'),
        "the translation unit ends with a newline"
    );

    // Root order and duplicates are not part of the output.
    let reordered = scratch.join("layout-reordered.c");
    let again = c_source(
        "pdb-c",
        &pdb,
        &["Bits", "Packet", "Packed", "Bits"],
        &reordered,
        &tcc,
    );
    assert!(again.success(), "{}", again.describe());
    assert_eq!(
        std::fs::read(&reordered).unwrap(),
        std::fs::read(&source_path).unwrap(),
        "root order does not change the generated bytes"
    );

    // A missing compiler is a typed failure and publishes nothing.
    let missing = scratch.join("layout-missing-tcc.c");
    let result = c_source(
        "pdb-c",
        &pdb,
        &["Packet"],
        &missing,
        Path::new("/nonexistent/sym2isf-tcc"),
    );
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(result.stderr.contains("TccCompile"), "{}", result.stderr);
    assert!(!missing.exists(), "no source is published without TCC");

    // A compiler that rejects the unit is a failure, not a publish.
    let rejected = scratch.join("layout-rejected.c");
    let result = c_source(
        "pdb-c",
        &pdb,
        &["Packet"],
        &rejected,
        Path::new("/bin/false"),
    );
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(result.stderr.contains("TccCompile"), "{}", result.stderr);
    assert!(!rejected.exists(), "a rejected unit publishes nothing");

    // An existing output is never replaced, even by a successful generation, and
    // it is checked before the input is even opened.
    let sentinel = scratch.join("layout-sentinel.c");
    std::fs::write(&sentinel, b"keep me\n").unwrap();
    let result = c_source("pdb-c", &pdb, &["Packet"], &sentinel, &tcc);
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(result.stderr.contains("OutputExists"), "{}", result.stderr);
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep me\n");
    let result = c_source(
        "pdb-c",
        Path::new("/nonexistent/probe.pdb"),
        &["Packet"],
        &sentinel,
        &tcc,
    );
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(result.stderr.contains("OutputExists"), "{}", result.stderr);
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep me\n");

    // The root set is mandatory: clap reports a usage error, not a conversion.
    let without_type = cli([
        OsStr::new("pdb-c"),
        pdb.as_os_str(),
        OsStr::new("--output"),
        sentinel.as_os_str(),
    ]);
    assert_eq!(without_type.status, Some(2), "{}", without_type.describe());

    let consumer = layout_consumer(&oracle);
    let stdout = tcc_run(&tcc, &scratch, &format!("{source}{consumer}"));
    assert_eq!(stdout, "layout-ok\n", "the consumer reported a mismatch");
}

#[cfg(target_os = "linux")]
#[test]
fn dwarf_c_tcc_round_trip() {
    let Some(cc) = tool("cc") else { return };
    let Some(tcc) = tool("tcc") else { return };
    let directory = tempdir("dwarf-c");
    let binary = build_host_probe(&directory, &cc, "probe", &["-gdwarf-4"]);
    let oracle = Oracle::parse(&run_binary(&binary));

    let source_path = directory.join("layout.c");
    let result = c_source(
        "dwarf-c",
        &binary,
        &["Packet", "Packed", "Bits"],
        &source_path,
        &tcc,
    );
    assert!(result.success(), "{}", result.describe());
    assert!(
        result.stdout.is_empty(),
        "stdout stays empty: {}",
        result.describe()
    );
    assert!(
        result.stderr.contains("TCC-checked C source"),
        "{}",
        result.stderr
    );
    let source = std::fs::read_to_string(&source_path).expect("generated source");

    // Root order and duplicates are not part of the output.
    let reordered = directory.join("layout-reordered.c");
    let again = c_source(
        "dwarf-c",
        &binary,
        &["Bits", "Packed", "Packet", "Packed"],
        &reordered,
        &tcc,
    );
    assert!(again.success(), "{}", again.describe());
    assert_eq!(
        std::fs::read(&reordered).unwrap(),
        std::fs::read(&source_path).unwrap(),
        "root order does not change the generated bytes"
    );

    // A relative `--tcc` resolves against the invoking directory, not the
    // private build directory the compiler runs in.
    let shim = directory.join("shim");
    std::fs::create_dir_all(&shim).unwrap();
    std::os::unix::fs::symlink(
        std::fs::canonicalize(&tcc).expect("tcc path"),
        shim.join("tcc"),
    )
    .expect("symlink to tcc");
    let relative = directory.join("layout-relative.c");
    let result = cli_in(
        Some(&directory),
        [
            OsStr::new("dwarf-c"),
            binary.as_os_str(),
            OsStr::new("--type"),
            OsStr::new("Packet"),
            OsStr::new("--output"),
            relative.as_os_str(),
            OsStr::new("--tcc"),
            OsStr::new("./shim/tcc"),
        ],
    );
    assert!(result.success(), "{}", result.describe());
    assert!(
        relative.is_file(),
        "a relative compiler path is resolved against the caller"
    );

    // The same consumer that checks the PDB document checks the DWARF one.
    let consumer = layout_consumer(&oracle);
    let stdout = tcc_run(&tcc, &directory, &format!("{source}{consumer}"));
    assert_eq!(stdout, "layout-ok\n", "the consumer reported a mismatch");
}

/// A document that only the generator can produce: hostile names, declarator
/// precedence, zero-length arrays, a forward-only pointer target and bit-fields
/// that start mid-byte and span nine bytes.
#[cfg(target_os = "linux")]
fn edge_document() -> IsfDocument {
    use sym2isf::isf::IntValue;
    use sym2isf::{BaseKind, BaseType, CompositeKind, Field, Target, TypeRef, UserType};

    fn base(kind: BaseKind, size: u64, signed: bool) -> BaseType {
        BaseType {
            kind,
            size,
            signed,
            endian: Endian::Little,
            alignment: None,
            unsupported_reason: None,
        }
    }
    fn reference(name: &str) -> TypeRef {
        TypeRef::Base {
            name: name.to_string(),
            qualifiers: Vec::new(),
        }
    }
    fn field(offset: u64, ty: TypeRef) -> Field {
        Field {
            offset,
            ty,
            anonymous: None,
        }
    }
    fn user(kind: CompositeKind, size: u64, fields: Vec<(&str, Field)>) -> UserType {
        UserType {
            kind,
            size,
            fields: fields
                .into_iter()
                .map(|(name, member)| (name.to_string(), member))
                .collect(),
            alignment: None,
            incomplete: None,
            unsupported_reason: None,
        }
    }
    fn pointer_to(ty: TypeRef) -> TypeRef {
        TypeRef::Pointer {
            subtype: Box::new(ty),
            size: None,
            qualifiers: Vec::new(),
            reference_kind: None,
        }
    }
    fn array_of(count: u64, ty: TypeRef) -> TypeRef {
        TypeRef::Array {
            count,
            subtype: Box::new(ty),
            qualifiers: Vec::new(),
        }
    }
    fn slice(
        offset: u64,
        bit_position: u64,
        bit_length: u64,
        storage: &str,
        declared: &str,
    ) -> Field {
        Field {
            offset,
            ty: TypeRef::Bitfield {
                bit_length,
                bit_position,
                ty: Box::new(reference(storage)),
                declared_type: Some(Box::new(reference(declared))),
            },
            anonymous: None,
        }
    }

    let mut document = IsfDocument::empty(
        Target {
            architecture: "x86_64".to_string(),
            pointer_size: 8,
            endian: Endian::Little,
        },
        None,
    );
    document
        .base_types
        .insert("void".to_string(), base(BaseKind::Void, 0, false));
    document
        .base_types
        .insert("uint8_t".to_string(), base(BaseKind::Int, 1, false));
    document
        .base_types
        .insert("int32_t".to_string(), base(BaseKind::Int, 4, true));
    document
        .base_types
        .insert("int64_t".to_string(), base(BaseKind::Int, 8, true));
    document
        .base_types
        .insert("uint64_t".to_string(), base(BaseKind::Int, 8, false));
    document
        .base_types
        .insert("wide_float".to_string(), base(BaseKind::Float, 16, true));
    document
        .base_types
        .insert("__isf_bitsi72".to_string(), base(BaseKind::Int, 9, true));
    document
        .base_types
        .insert("__isf_bitsu72".to_string(), base(BaseKind::Int, 9, false));
    document
        .base_types
        .insert("__isf_bitsu8".to_string(), base(BaseKind::Int, 1, false));

    document.user_types.insert(
        "Outer::Thing".to_string(),
        user(
            CompositeKind::Struct,
            4,
            vec![("int", field(0, reference("int32_t")))],
        ),
    );
    document.user_types.insert(
        "Outer_3a_3aThing".to_string(),
        user(
            CompositeKind::Struct,
            4,
            vec![("9x", field(0, reference("int32_t")))],
        ),
    );
    // Only reachable through a pointer: it must stay a declaration, so its
    // 16-byte float member never has to become a C type.
    document.user_types.insert(
        "UnusedBad".to_string(),
        user(
            CompositeKind::Struct,
            16,
            vec![("wide", field(0, reference("wide_float")))],
        ),
    );
    document.user_types.insert(
        "ZeroUnion".to_string(),
        user(
            CompositeKind::Union,
            1,
            vec![
                ("tag", field(0, reference("uint8_t"))),
                ("bytes", field(0, array_of(0, reference("uint8_t")))),
            ],
        ),
    );
    document.user_types.insert(
        "Edge".to_string(),
        user(
            CompositeKind::Struct,
            56,
            vec![
                (
                    "array_pointer",
                    field(0, pointer_to(array_of(3, reference("int32_t")))),
                ),
                (
                    "callbacks",
                    field(
                        8,
                        array_of(
                            2,
                            pointer_to(TypeRef::Function {
                                return_type: Box::new(reference("int32_t")),
                                parameters: vec![sym2isf::Parameter {
                                    name: None,
                                    ty: reference("int32_t"),
                                }],
                                variadic: None,
                                calling_convention: None,
                                qualifiers: Vec::new(),
                            }),
                        ),
                    ),
                ),
                (
                    "left",
                    field(
                        24,
                        TypeRef::Struct {
                            name: "Outer::Thing".to_string(),
                            qualifiers: Vec::new(),
                        },
                    ),
                ),
                (
                    "right",
                    field(
                        28,
                        TypeRef::Struct {
                            name: "Outer_3a_3aThing".to_string(),
                            qualifiers: Vec::new(),
                        },
                    ),
                ),
                (
                    "code",
                    field(
                        32,
                        TypeRef::Enum {
                            name: "Wide".to_string(),
                            qualifiers: Vec::new(),
                        },
                    ),
                ),
                (
                    "unused",
                    field(
                        40,
                        pointer_to(TypeRef::Struct {
                            name: "UnusedBad".to_string(),
                            qualifiers: Vec::new(),
                        }),
                    ),
                ),
                ("tail", field(48, array_of(0, reference("uint8_t")))),
                (
                    "zero",
                    field(
                        48,
                        TypeRef::Union {
                            name: "ZeroUnion".to_string(),
                            qualifiers: Vec::new(),
                        },
                    ),
                ),
            ],
        ),
    );
    document.user_types.insert(
        "SignedBits64".to_string(),
        user(
            CompositeKind::Struct,
            9,
            vec![("value", slice(0, 3, 64, "__isf_bitsi72", "int64_t"))],
        ),
    );
    document.user_types.insert(
        "UnsignedBits64".to_string(),
        user(
            CompositeKind::Struct,
            9,
            vec![("value", slice(0, 3, 64, "__isf_bitsu72", "uint64_t"))],
        ),
    );
    document
        .typedefs
        .insert("keep_t".to_string(), reference("uint8_t"));
    // A pointer to a function returning a pointer, and a pointer to an array of
    // pointers: both put a `*` on the far side of a suffix.
    document.user_types.insert(
        "Factory".to_string(),
        user(
            CompositeKind::Struct,
            16,
            vec![
                (
                    "make",
                    field(
                        0,
                        pointer_to(TypeRef::Function {
                            return_type: Box::new(pointer_to(reference("int32_t"))),
                            parameters: Vec::new(),
                            variadic: None,
                            calling_convention: None,
                            qualifiers: Vec::new(),
                        }),
                    ),
                ),
                (
                    "rows",
                    field(8, pointer_to(array_of(3, pointer_to(reference("int32_t"))))),
                ),
            ],
        ),
    );
    // `A` sorts before `Zed`: the alias is reached first through a pointer and
    // then by value, so only a stronger second visit orders the definition.
    document.user_types.insert(
        "Zed".to_string(),
        user(
            CompositeKind::Struct,
            8,
            vec![("value", field(0, reference("int64_t")))],
        ),
    );
    document.typedefs.insert(
        "Alias".to_string(),
        TypeRef::Struct {
            name: "Zed".to_string(),
            qualifiers: Vec::new(),
        },
    );
    document.user_types.insert(
        "A".to_string(),
        user(
            CompositeKind::Struct,
            16,
            vec![
                (
                    "p",
                    field(
                        0,
                        pointer_to(TypeRef::Typedef {
                            name: "Alias".to_string(),
                            qualifiers: Vec::new(),
                        }),
                    ),
                ),
                (
                    "v",
                    field(
                        8,
                        TypeRef::Typedef {
                            name: "Alias".to_string(),
                            qualifiers: Vec::new(),
                        },
                    ),
                ),
            ],
        ),
    );
    // `A2` sorts before `Zed2`, and only the prototype's array element needs the
    // definition.
    document.user_types.insert(
        "Zed2".to_string(),
        user(
            CompositeKind::Struct,
            4,
            vec![("value", field(0, reference("int32_t")))],
        ),
    );
    document.user_types.insert(
        "A2".to_string(),
        user(
            CompositeKind::Struct,
            8,
            vec![(
                "cb",
                field(
                    0,
                    pointer_to(TypeRef::Function {
                        return_type: Box::new(reference("void")),
                        parameters: vec![sym2isf::Parameter {
                            name: None,
                            ty: pointer_to(array_of(
                                2,
                                TypeRef::Struct {
                                    name: "Zed2".to_string(),
                                    qualifiers: Vec::new(),
                                },
                            )),
                        }],
                        variadic: None,
                        calling_convention: None,
                        qualifiers: Vec::new(),
                    }),
                ),
            )],
        ),
    );
    // A const volatile bit-field has no setter and is read through volatile bytes.
    document.user_types.insert(
        "ConstVolatile".to_string(),
        user(
            CompositeKind::Struct,
            2,
            vec![
                (
                    "keep",
                    Field {
                        offset: 0,
                        ty: TypeRef::Bitfield {
                            bit_length: 4,
                            bit_position: 0,
                            ty: Box::new(reference("__isf_bitsu8")),
                            declared_type: Some(Box::new(TypeRef::Typedef {
                                name: "keep_t".to_string(),
                                qualifiers: vec![
                                    sym2isf::Qualifier::Const,
                                    sym2isf::Qualifier::Volatile,
                                ],
                            })),
                        },
                        anonymous: None,
                    },
                ),
                ("plain", field(1, reference("uint8_t"))),
            ],
        ),
    );
    // A function whose return type needs parentheses in the declarator.
    document.functions.insert(
        "factory".to_string(),
        sym2isf::isf::Function {
            address: None,
            return_type: pointer_to(TypeRef::Function {
                return_type: Box::new(reference("int32_t")),
                parameters: vec![sym2isf::Parameter {
                    name: None,
                    ty: reference("int32_t"),
                }],
                variadic: None,
                calling_convention: None,
                qualifiers: Vec::new(),
            }),
            parameters: Vec::new(),
            variadic: None,
            calling_convention: None,
        },
    );
    document.enums.insert(
        "Wide".to_string(),
        sym2isf::isf::EnumType {
            size: 8,
            base: Some("uint64_t".to_string()),
            constants: BTreeMap::from([
                (String::new(), IntValue::Unsigned(0)),
                ("empty".to_string(), IntValue::Unsigned(1)),
                ("max".to_string(), IntValue::Unsigned(u64::MAX)),
            ]),
        },
    );
    document
}

#[cfg(target_os = "linux")]
#[test]
fn c_generation_tcc_edges() {
    let Some(tcc) = tool("tcc") else { return };
    let directory = tempdir("c-edges");
    let document = edge_document();
    let source = sym2isf::c::generate(
        &document,
        &sym2isf::c::Request {
            types: &[
                "Edge",
                "SignedBits64",
                "UnsignedBits64",
                "ConstVolatile",
                "Factory",
                "A",
                "A2",
            ],
            functions: &["factory"],
            ..sym2isf::c::Request::default()
        },
    )
    .expect("the edge document is describable");
    assert!(
        !source.contains("s2c_s_UnusedBad {"),
        "a pointer-only target stays a declaration"
    );
    assert!(
        !source.contains("s2c_s_ConstVolatile_set_keep"),
        "a const bit-field has no setter"
    );

    let consumer = r#"
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(condition) do { if (!(condition)) { printf("failed: %s\n", #condition); failures = 1; } } while (0)

static int32_t plus_one(int32_t value) { return value + 1; }
static int32_t *make_value(void) { return 0; }
static void take_rows(s2c_s_Zed2 (*rows)[2]) { (void)rows; }


int main(void)
{
    int32_t values[3] = {10, 20, 30};
    s2c_s_Edge edge;
    memset(&edge, 0, sizeof edge);
    edge.array_pointer = &values;
    CHECK((*edge.array_pointer)[2] == 30);
    edge.callbacks[0] = plus_one;
    CHECK(edge.callbacks[0](6) == 7);
    edge.left.s2c_f_int = 7;
    edge.right.s2c_f_9x = 9;
    CHECK(edge.left.s2c_f_int == 7);
    CHECK(edge.right.s2c_f_9x == 9);
    edge.unused = 0;
    CHECK(edge.unused == 0);
    CHECK(sizeof(s2c_s_Edge) == 56);
    CHECK(offsetof(s2c_s_Edge, array_pointer) == 0);
    CHECK(offsetof(s2c_s_Edge, callbacks) == 8);
    CHECK(offsetof(s2c_s_Edge, left) == 24);
    CHECK(offsetof(s2c_s_Edge, right) == 28);
    CHECK(offsetof(s2c_s_Edge, code) == 32);
    CHECK(offsetof(s2c_s_Edge, unused) == 40);
    CHECK(offsetof(s2c_s_Edge, tail) == 48);
    CHECK(offsetof(s2c_s_Edge, zero) == 48);
    CHECK(sizeof(s2c_u_ZeroUnion) == 1);
    CHECK(s2c_e_Wide_empty == 0);
    CHECK(s2c_e_Wide_empty_2 == 1);
    CHECK(s2c_e_Wide_max == UINT64_MAX);

    {
        s2c_s_SignedBits64 signed_bits;
        unsigned char *raw = (unsigned char *)&signed_bits;
        memset(&signed_bits, 0, sizeof signed_bits);
        raw[0] = 0x05;
        raw[8] = 0xa8;
        s2c_s_SignedBits64_set_value(&signed_bits, INT64_MIN);
        CHECK(s2c_s_SignedBits64_get_value(&signed_bits) == INT64_MIN);
        {
            const unsigned char expected[9] = {0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac};
            CHECK(memcmp(raw, expected, sizeof expected) == 0);
        }
        s2c_s_SignedBits64_set_value(&signed_bits, -1);
        CHECK(s2c_s_SignedBits64_get_value(&signed_bits) == -1);
        {
            const unsigned char expected[9] = {0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaf};
            CHECK(memcmp(raw, expected, sizeof expected) == 0);
        }
        s2c_s_SignedBits64_set_value(&signed_bits, 0);
        CHECK(s2c_s_SignedBits64_get_value(&signed_bits) == 0);
        {
            const unsigned char expected[9] = {0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8};
            CHECK(memcmp(raw, expected, sizeof expected) == 0);
        }
        CHECK(sizeof(s2c_s_SignedBits64) == 9);
    }

    {
        s2c_s_UnsignedBits64 unsigned_bits;
        unsigned char *raw = (unsigned char *)&unsigned_bits;
        memset(&unsigned_bits, 0, sizeof unsigned_bits);
        raw[0] = 0x05;
        raw[8] = 0xa8;
        s2c_s_UnsignedBits64_set_value(&unsigned_bits, UINT64_MAX);
        CHECK(s2c_s_UnsignedBits64_get_value(&unsigned_bits) == UINT64_MAX);
        {
            const unsigned char expected[9] = {0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaf};
            CHECK(memcmp(raw, expected, sizeof expected) == 0);
        }
        s2c_s_UnsignedBits64_set_value(&unsigned_bits, 0);
        CHECK(s2c_s_UnsignedBits64_get_value(&unsigned_bits) == 0);
        {
            const unsigned char expected[9] = {0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8};
            CHECK(memcmp(raw, expected, sizeof expected) == 0);
        }
        CHECK(sizeof(s2c_s_UnsignedBits64) == 9);
    }

    {
        s2c_s_Factory factory;
        int32_t *row_values[3];
        memset(&factory, 0, sizeof factory);
        factory.make = make_value;
        CHECK(factory.make == make_value);
        factory.rows = &row_values;
        CHECK((*factory.rows)[0] == row_values[0]);
        CHECK((*factory.rows)[2] == row_values[2]);
        CHECK(sizeof(s2c_s_Factory) == 16);
    }

    {
        s2c_s_A a;
        memset(&a, 0, sizeof a);
        a.p = &a.v;
        CHECK(a.p == &a.v);
        a.v.value = 5;
        CHECK(a.p->value == 5);
        CHECK(sizeof(s2c_s_A) == 16);
        CHECK(sizeof(s2c_s_Zed) == 8);
    }

    {
        s2c_s_A2 a2;
        memset(&a2, 0, sizeof a2);
        a2.cb = take_rows;
        CHECK(a2.cb == take_rows);
        CHECK(sizeof(s2c_s_A2) == 8);
    }

    {
        s2c_s_ConstVolatile cv;
        memset(&cv, 0, sizeof cv);
        ((unsigned char *)&cv)[0] = 0x0d;
        cv.plain = 0x7f;
        CHECK(s2c_s_ConstVolatile_get_keep(&cv) == 13);
        CHECK(cv.plain == 0x7f);
        CHECK(((const unsigned char *)&cv)[0] == 0x0d);
        CHECK(sizeof(s2c_s_ConstVolatile) == 2);
    }

    printf("%s\n", failures ? "edges-failed" : "edges-ok");
    return failures;
}
"#;
    // A prototype is a declaration, so it can only be type-checked at compile
    // time: a function returning a pointer to a function keeps the parameter
    // list of the outer function, and the assignment below fails otherwise.
    tcc_compile_only(
        &tcc,
        &directory,
        &format!(
            "{source}\n\
             typedef int32_t (*s2c_expected_inner)(int32_t);\n\
             typedef s2c_expected_inner (*s2c_expected_factory)(void);\n\
             s2c_expected_factory s2c_factory_check = factory;\n"
        ),
        "factory",
    );
    let stdout = tcc_run(&tcc, &directory, &format!("{source}{consumer}"));
    assert_eq!(
        stdout, "edges-ok\n",
        "the edge consumer reported a mismatch"
    );
}

// ---------------------------------------------------------------------------
// Function declarations in C, checked by a real TCC
// ---------------------------------------------------------------------------

/// A consumer that checks the declared prototype against an independently
/// written type: assigning the function to a pointer of the expected shape, and
/// defining it with the same signature, both fail to compile if the declared
/// types disagree. The document name is kept verbatim, so this is the
/// type-equivalence proof.
#[cfg(target_os = "linux")]
const FUNCTION_DEFINITION: &str = r#"
#include <stdint.h>

typedef int32_t (*s2c_expected_callback)(s2c_s_Packet *, int32_t);
s2c_expected_callback s2c_expected_callback_value = packet_callback;

int32_t packet_callback(s2c_s_Packet *packet, int32_t delta)
{
    packet->value += delta;
    return packet->value;
}
"#;

#[cfg(target_os = "linux")]
fn address_consumer(address: u64, name: &str) -> String {
    format!(
        r#"
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(condition) do {{ if (!(condition)) {{ printf("failed: %s\n", #condition); failures = 1; }} }} while (0)

int main(void)
{{
    const uint64_t expected = 0x{address:016x}ULL;
    size_t index;
    int found = 0;
    for (index = 0; index < sizeof(s2c_addresses) / sizeof(s2c_addresses[0]); index++) {{
        if (strcmp(s2c_addresses[index].name, "{name}") == 0) {{
            found = 1;
            CHECK(s2c_addresses[index].address == expected);
        }}
    }}
    CHECK(found);
    printf("%s\n", failures ? "addresses-failed" : "addresses-ok");
    return failures;
}}
"#
    )
}

#[cfg(target_os = "linux")]
#[test]
fn pdb_c_tcc_functions() {
    let Some(directory) = pdb_artifacts() else {
        return;
    };
    let Some(tcc) = tool("tcc") else { return };
    let Some(nm) = tool("nm") else { return };
    let oracle = {
        let text = std::fs::read_to_string(directory.join("oracle.json")).expect("oracle");
        Oracle::parse(&text)
    };
    let pdb = directory.join("probe.pdb");
    let scratch = tempdir("pdb-c-functions");

    // A signature needs no address, so this runs without an image or base.
    let source_path = scratch.join("fn.c");
    let result = c_args(
        "pdb-c",
        &pdb,
        &[
            OsStr::new("--type"),
            OsStr::new("Packet"),
            OsStr::new("--function"),
            OsStr::new("packet_callback"),
        ],
        &source_path,
        &tcc,
    );
    assert!(result.success(), "{}", result.describe());
    assert!(result.stdout.is_empty(), "{}", result.describe());
    let source = std::fs::read_to_string(&source_path).expect("generated source");
    assert!(source.contains("extern "), "{source}");
    assert!(!source.contains("s2c_addresses"), "{source}");

    // The unit itself exports nothing: no prototype becomes a bound symbol.
    let symbols = global_symbols(&tcc, &nm, &scratch, &source, "generated");
    assert!(symbols.is_empty(), "unexpected exports: {symbols:?}");

    // The prototype's types match a real definition, and leaving it out of the
    // unit would not; TCC reports conflicting types otherwise.
    global_symbols(
        &tcc,
        &nm,
        &scratch,
        &format!("{source}{FUNCTION_DEFINITION}"),
        "definition",
    );

    // Selector order and duplicates are not part of the output.
    let reordered = scratch.join("fn-reordered.c");
    let again = c_args(
        "pdb-c",
        &pdb,
        &[
            OsStr::new("--function"),
            OsStr::new("main"),
            OsStr::new("--function"),
            OsStr::new("packet_callback"),
            OsStr::new("--function"),
            OsStr::new("main"),
        ],
        &reordered,
        &tcc,
    );
    assert!(again.success(), "{}", again.describe());
    let forward = c_args(
        "pdb-c",
        &pdb,
        &[
            OsStr::new("--function"),
            OsStr::new("packet_callback"),
            OsStr::new("--function"),
            OsStr::new("main"),
        ],
        &scratch.join("fn-forward.c"),
        &tcc,
    );
    assert!(forward.success(), "{}", forward.describe());
    assert_eq!(
        std::fs::read(&reordered).unwrap(),
        std::fs::read(scratch.join("fn-forward.c")).unwrap(),
        "selector order does not change the generated bytes"
    );

    // The recorded address is opt-in and needs the image.
    let with_addresses = scratch.join("fn-addresses.c");
    let result = c_args(
        "pdb-c",
        &pdb,
        &[
            OsStr::new("--function"),
            OsStr::new("packet_callback"),
            OsStr::new("--with-addresses"),
            OsStr::new("--image"),
            directory.join("probe.exe").as_os_str(),
        ],
        &with_addresses,
        &tcc,
    );
    assert!(result.success(), "{}", result.describe());
    let table = std::fs::read_to_string(&with_addresses).expect("address table source");
    let consumer = address_consumer(oracle.addresses["packet_callback"], "packet_callback");
    let stdout = tcc_run(&tcc, &scratch, &format!("{table}{consumer}"));
    assert_eq!(stdout, "addresses-ok\n", "the address table is wrong");

    // Without an image base there are no addresses, and nothing is published.
    let no_base = scratch.join("fn-no-base.c");
    let result = c_args(
        "pdb-c",
        &pdb,
        &[
            OsStr::new("--function"),
            OsStr::new("packet_callback"),
            OsStr::new("--with-addresses"),
        ],
        &no_base,
        &tcc,
    );
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(
        result.stderr.contains("MissingImageBase"),
        "{}",
        result.stderr
    );
    assert!(!no_base.exists(), "no source without addresses");

    // An unknown selector is a typed failure and publishes nothing.
    let unknown = scratch.join("fn-unknown.c");
    let result = c_args(
        "pdb-c",
        &pdb,
        &[OsStr::new("--function"), OsStr::new("no_such_function")],
        &unknown,
        &tcc,
    );
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(result.stderr.contains("CGeneration"), "{}", result.stderr);
    assert!(
        result.stderr.contains("function `no_such_function`"),
        "{}",
        result.stderr
    );
    assert!(!unknown.exists(), "no source for a rejected selection");
}

/// `Signatures` collects what a declaration needs and nothing that needs an
/// address, so it works without an image base.
#[cfg(unix)]
#[test]
fn signature_mode_drops_addresses() {
    use sym2isf::{DebugInput, Detail};

    let Some(cc) = tool("cc") else { return };
    let directory = tempdir("signatures");
    build_host_probe(&directory, &cc, "probe", &["-gdwarf-4"]);
    // The object carries the DWARF on every host (on macOS the linked image does
    // not), and an unlinked object is exactly what a signature-only conversion
    // must handle without addresses.
    let object = directory.join("probe.o");
    let document = sym2isf::convert(&DebugInput::Dwarf {
        image: object,
        debug_file: None,
        architecture: None,
        detail: Detail::Signatures,
    })
    .expect("a signatures conversion");
    assert!(!document.functions.is_empty(), "signatures are collected");
    assert!(
        document
            .functions
            .values()
            .all(|entry| entry.address.is_none()),
        "no function carries an address"
    );
    assert!(document.symbols.is_empty(), "object symbols stay out");
    assert!(
        document.metadata.sym2isf.image_base.is_none(),
        "no image base is claimed"
    );
    document.validate().expect("the document validates");
}

#[cfg(target_os = "linux")]
#[test]
fn dwarf_c_tcc_functions() {
    let Some(cc) = tool("cc") else { return };
    let Some(tcc) = tool("tcc") else { return };
    let Some(nm) = tool("nm") else { return };
    let directory = tempdir("dwarf-c-functions");
    let binary = build_host_probe(&directory, &cc, "probe", &["-gdwarf-4"]);
    let oracle = Oracle::parse(&run_binary(&binary));

    let source_path = directory.join("fn.c");
    let result = c_args(
        "dwarf-c",
        &binary,
        &[
            OsStr::new("--type"),
            OsStr::new("Packet"),
            OsStr::new("--function"),
            OsStr::new("packet_callback"),
        ],
        &source_path,
        &tcc,
    );
    assert!(result.success(), "{}", result.describe());
    let source = std::fs::read_to_string(&source_path).expect("generated source");
    let symbols = global_symbols(&tcc, &nm, &directory, &source, "generated");
    assert!(symbols.is_empty(), "unexpected exports: {symbols:?}");
    global_symbols(
        &tcc,
        &nm,
        &directory,
        &format!("{source}{FUNCTION_DEFINITION}"),
        "definition",
    );

    // DWARF carries addresses itself, so no image base is needed here.
    let with_addresses = directory.join("fn-addresses.c");
    let result = c_args(
        "dwarf-c",
        &binary,
        &[
            OsStr::new("--function"),
            OsStr::new("packet_callback"),
            OsStr::new("--with-addresses"),
        ],
        &with_addresses,
        &tcc,
    );
    assert!(result.success(), "{}", result.describe());
    let table = std::fs::read_to_string(&with_addresses).expect("address table source");
    let consumer = address_consumer(oracle.addresses["packet_callback"], "packet_callback");
    let stdout = tcc_run(&tcc, &directory, &format!("{table}{consumer}"));
    assert_eq!(stdout, "addresses-ok\n", "the address table is wrong");

    // `--all-functions` declares exactly the document's table.
    let json = directory.join("probe.json");
    assert!(convert_binary(&binary, &json).success());
    let document = load_document(&json);
    let expected = document["functions"].as_object().expect("functions").len();
    assert!(expected >= 4, "the probe records its functions: {expected}");
    let every = directory.join("fn-all.c");
    let result = c_args(
        "dwarf-c",
        &binary,
        &[OsStr::new("--all-functions")],
        &every,
        &tcc,
    );
    assert!(result.success(), "{}", result.describe());
    let all = std::fs::read_to_string(&every).expect("all functions source");
    let declared = all
        .lines()
        .filter(|line| line.starts_with("extern "))
        .count();
    assert_eq!(declared, expected, "--all-functions declares every entry");
    global_symbols(&tcc, &nm, &directory, &all, "all");
}

// ---------------------------------------------------------------------------
// SDK view: a callable struct of pointers, resolved from a module base
// ---------------------------------------------------------------------------

/// Build a shared object from the probe fixture. The SDK view binds a module
/// base, so the target has to be loadable with `dlopen`.
#[cfg(target_os = "linux")]
fn build_shared_probe(directory: &Path, compiler: &Path) -> PathBuf {
    let object = directory.join("shared.o");
    compile(
        Command::new(compiler)
            .args([
                "-O0",
                "-g",
                "-gdwarf-4",
                "-fno-eliminate-unused-debug-types",
                "-fPIC",
                "-c",
            ])
            .arg(PROBE_C)
            .arg("-o")
            .arg(&object),
    );
    let library = directory.join("libprobe.so");
    compile(
        Command::new(compiler)
            .arg("-shared")
            .arg(&object)
            .arg("-o")
            .arg(&library),
    );
    library
}

/// Calls the target through the generated struct, never through a symbol.
#[cfg(target_os = "linux")]
const SDK_CONSUMER: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include "sdk.h"

static int failures = 0;
static int resolve_failures = 0;
static uintptr_t module_base;
#define CHECK(condition) do { if (!(condition)) { printf("failed: %s\n", #condition); failures = 1; } } while (0)

/* The caller's resolver: the header asks by source name, we answer with the
   module base plus the offset it recorded. A hardcoded answer would do here. */
static s2c_entry resolve_entry(const char *name, uintptr_t offset)
{
    if (strcmp(name, "packet_callback") != 0 && strcmp(name, "endian_name") != 0) {
        resolve_failures = 1;
    }
    return (s2c_entry)(module_base + offset);
}

int main(int argc, char **argv)
{
    void *handle;
    void *anchor;
    Dl_info info;
    struct s2c_api api;
    struct Packet packet;
    const char *endian;
    int32_t result;

    CHECK(argc == 2);
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    CHECK(handle != 0);
    /* Any exported symbol of the module gives its load bias. */
    anchor = dlsym(handle, "packet_global");
    CHECK(anchor != 0);
    CHECK(dladdr(anchor, &info) != 0);
    module_base = (uintptr_t)info.dli_fbase;
    s2c_bind(&api, resolve_entry);
    CHECK(resolve_failures == 0);
    CHECK(api.packet_callback != 0);
    CHECK(api.endian_name != 0);

    memset(&packet, 0, sizeof packet);
    packet.value = 5;
    result = api.packet_callback(&packet, 3);
    CHECK(result == 8);
    CHECK(packet.value == 8);

    endian = api.endian_name();
    CHECK(endian != 0);
    CHECK(strcmp(endian, "little") == 0);

    printf("%s\n", failures ? "sdk-failed" : "sdk-ok");
    return failures;
}
"#;

#[cfg(target_os = "linux")]
#[test]
fn dwarf_c_sdk_round_trip() {
    let Some(cc) = tool("cc") else { return };
    let Some(tcc) = tool("tcc") else { return };
    let directory = tempdir("dwarf-c-sdk");
    let library = build_shared_probe(&directory, &cc);

    let header = directory.join("sdk.h");
    let result = c_args(
        "dwarf-c",
        &library,
        &[
            OsStr::new("--emit"),
            OsStr::new("sdk"),
            OsStr::new("--type"),
            OsStr::new("Packet"),
            // Bit-fields bring the generated accessors into the header.
            OsStr::new("--type"),
            OsStr::new("Bits"),
            OsStr::new("--function"),
            OsStr::new("packet_callback"),
            OsStr::new("--function"),
            OsStr::new("endian_name"),
        ],
        &header,
        &tcc,
    );
    assert!(result.success(), "{}", result.describe());
    assert!(result.stdout.is_empty(), "{}", result.describe());
    let source = std::fs::read_to_string(&header).expect("sdk header");
    assert!(source.contains("struct s2c_api {"), "{source}");
    assert!(
        source.contains("static inline void s2c_bind(struct s2c_api *api, s2c_resolver resolve)"),
        "{source}"
    );
    assert!(!source.contains("extern "), "{source}");
    // Resolution is injected; the header passes the name and the recorded offset.
    assert!(
        source.contains("resolve(\"packet_callback\", (uintptr_t)0x"),
        "{source}"
    );

    // A header is included by a consumer, not compiled as its own unit: it must
    // be clean under a strict real compiler, including accessors nobody calls.
    let probe = directory.join("header-only.c");
    std::fs::write(&probe, "#include \"sdk.h\"\nint main(void) { return 0; }\n")
        .expect("header probe");
    let compiled = Command::new(&cc)
        .args(["-Wall", "-Wextra", "-Werror", "-c"])
        .arg("-I")
        .arg(&directory)
        .arg(&probe)
        .arg("-o")
        .arg(directory.join("header-only.o"))
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", cc.display()));
    assert!(
        compiled.status.success(),
        "the SDK header is not warning-clean: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let consumer = directory.join("consumer.c");
    std::fs::write(&consumer, SDK_CONSUMER).expect("consumer");
    let output = Command::new(&tcc)
        .arg("-Werror")
        .arg(format!("-I{}", directory.display()))
        .arg("-run")
        .arg(&consumer)
        .arg(&library)
        .current_dir(&directory)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", tcc.display()));
    assert!(
        output.status.success(),
        "SDK consumer failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "sdk-ok\n",
        "the SDK consumer reported a mismatch"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn pdb_c_sdk_offsets_are_relative_to_the_image_base() {
    let Some(directory) = pdb_artifacts() else {
        return;
    };
    let Some(tcc) = tool("tcc") else { return };
    let pdb = directory.join("probe.pdb");
    let image = directory.join("probe.exe");
    let scratch = tempdir("pdb-c-sdk");

    let header = scratch.join("sdk.h");
    let result = c_args(
        "pdb-c",
        &pdb,
        &[
            OsStr::new("--emit"),
            OsStr::new("sdk"),
            OsStr::new("--function"),
            OsStr::new("packet_callback"),
            OsStr::new("--image"),
            image.as_os_str(),
        ],
        &header,
        &tcc,
    );
    assert!(result.success(), "{}", result.describe());
    let source = std::fs::read_to_string(&header).expect("sdk header");
    assert!(!source.contains("extern "), "{source}");

    // The offset is the recorded address minus the image base, not the address.
    let json = scratch.join("probe.json");
    assert!(convert_pdb(&pdb, &json, &["--image", image.to_str().unwrap()]).success());
    let document = load_document(&json);
    let address = document["functions"]["packet_callback"]["address"]
        .as_u64()
        .expect("recorded address");
    let base = document["metadata"]["sym2isf"]["image_base"]
        .as_u64()
        .expect("image base");
    let offset = address - base;
    assert!(
        source.contains(&format!(
            "resolve(\"packet_callback\", (uintptr_t)0x{offset:016x}ULL)"
        )),
        "expected offset {offset:#x} in {source}"
    );
    assert!(
        !source.contains(&format!("(uintptr_t)0x{address:016x}ULL")),
        "the absolute address must not be passed: {source}"
    );
}
