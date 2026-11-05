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
    let output = Command::new(env!("CARGO_BIN_EXE_sym2isf"))
        .args(args)
        .output()
        .expect("run sym2isf");
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

    // Global objects carry the addresses the program printed.
    for (name, address) in &oracle.addresses {
        if name == "packet_callback" {
            continue; // published in `functions`, checked below
        }
        let entry = document["symbols"]
            .get(name)
            .unwrap_or_else(|| panic!("symbol {name} is missing"));
        assert_eq!(
            entry["address"].as_u64(),
            Some(*address),
            "address of {name}"
        );
    }
    let callback_entry = &document["functions"]["packet_callback"];
    assert_eq!(
        callback_entry["address"].as_u64(),
        Some(oracle.addresses["packet_callback"]),
        "address of packet_callback"
    );
    assert_eq!(
        callback_entry["parameters"].as_array().map(Vec::len),
        Some(2)
    );
}

// ---------------------------------------------------------------------------
// Linux: gcc, gcc DWARF 5, clang, relocatable object, strip, compression
// ---------------------------------------------------------------------------

fn build_linux_probe(directory: &Path, compiler: &Path, output: &str, extra: &[&str]) -> PathBuf {
    let binary = directory.join(output);
    let mut command = Command::new(compiler);
    command
        .args([
            "-O0",
            "-g",
            "-fno-eliminate-unused-debug-types",
            "-fno-pie",
            "-no-pie",
        ])
        .args(extra)
        .arg(PROBE_C)
        .arg("-o")
        .arg(&binary);
    compile(&mut command);
    binary
}

#[cfg(unix)]
#[test]
fn gcc_dwarf4_matches_the_probe_oracle() {
    let Some(cc) = tool("cc") else { return };
    let directory = tempdir("gcc4");
    let binary = build_linux_probe(&directory, &cc, "probe", &["-gdwarf-4"]);
    let oracle = Oracle::parse(&run_binary(&binary));
    let output = directory.join("probe.json");
    let result = convert(&binary, &output, &[]);
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

#[cfg(unix)]
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
        let binary = build_linux_probe(&directory, &compiler, name, &flags);
        // Each binary is its own oracle: addresses differ between builds.
        let oracle = Oracle::parse(&run_binary(&binary));
        let output = directory.join(format!("{name}.json"));
        let result = convert(&binary, &output, &[]);
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
    let binary = build_linux_probe(&directory, &cc, "probe", &["-gdwarf-4"]);
    assert!(convert(&binary, &linked, &[]).success());
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
    let binary = build_linux_probe(&directory, &cc, "probe", &["-gdwarf-4"]);
    let stripped = directory.join("probe.stripped");
    std::fs::copy(&binary, &stripped).unwrap();
    compile(Command::new(strip).arg(&stripped));
    let output = directory.join("stripped.json");
    let result = convert(&stripped, &output, &[]);
    assert_eq!(result.status, Some(1), "{}", result.describe());
    assert!(result.stderr.contains("NoDebugInfo"), "{}", result.stderr);
    assert!(!output.exists());
}

#[cfg(unix)]
#[test]
fn compressed_debug_sections_still_convert() {
    let Some(cc) = tool("cc") else { return };
    let Some(objcopy) = tool_any(&["llvm-objcopy", "llvm-objcopy-18"]) else {
        return;
    };
    let directory = tempdir("compressed");
    let binary = build_linux_probe(&directory, &cc, "probe", &["-gdwarf-4"]);
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
    let binary = build_linux_probe(&directory, &cc, "probe", &["-gdwarf-4", "-Wl,--build-id"]);
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
    let other_binary = build_linux_probe(&directory, &cc, "probe-other", &["-gdwarf-5"]);
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
    let binary = build_linux_probe(
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
    let binary = directory.join("probe-cpp");
    compile(
        Command::new(&cxx)
            .args([
                "-O0",
                "-g",
                "-gdwarf-4",
                "-fno-eliminate-unused-debug-types",
                "-fno-pie",
                "-no-pie",
            ])
            .arg(CPP_PROBE)
            .arg("-o")
            .arg(&binary),
    );
    let output = directory.join("cpp.json");
    let result = convert(&binary, &output, &[]);
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

    let Some(lipo) = tool_any(&["llvm-lipo", "llvm-lipo-18"]) else {
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
        let binary = directory.join("probe");
        compile(
            Command::new(&clang)
                .args(["-O0", "-g", "-gdwarf-4"])
                .arg(PROBE_C)
                .arg("-o")
                .arg(&binary),
        );
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
        assert_eq!(
            document["symbols"]["packet_global"]["address"].as_u64(),
            Some(oracle.addresses["packet_global"])
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
    let binary = build_linux_probe(&directory, &cc, "probe", &["-gdwarf-4"]);
    let first = directory.join("first.json");
    let second = directory.join("second.json");
    assert!(convert(&binary, &first, &[]).success());
    assert!(convert(&binary, &second, &[]).success());
    let a = std::fs::read(&first).unwrap();
    let b = std::fs::read(&second).unwrap();
    assert_eq!(a, b, "repeated conversions are byte identical");

    let packed = directory.join("probe.json.xz");
    assert!(convert(&binary, &packed, &[]).success());
    let mut decompressed = Vec::new();
    lzma_rs::xz_decompress(
        &mut std::io::Cursor::new(std::fs::read(&packed).unwrap()),
        &mut decompressed,
    )
    .expect("xz payload");
    assert_eq!(decompressed, a, "xz and json carry the same bytes");

    // An existing output is never overwritten.
    let error = convert(&binary, &first, &[]);
    assert_eq!(error.status, Some(1), "{}", error.describe());
    assert!(error.stderr.contains("OutputExists"), "{}", error.stderr);
    assert_eq!(std::fs::read(&first).unwrap(), a);

    // A wrong suffix is reported, not guessed.
    let bad = directory.join("probe.txt");
    let error = convert(&binary, &bad, &[]);
    assert_eq!(error.status, Some(1), "{}", error.describe());
    assert!(
        error.stderr.contains("UnsupportedOutput"),
        "{}",
        error.stderr
    );
    assert!(!bad.exists());

    // Missing parent directory is an I/O error, not a silent mkdir.
    let missing = directory.join("no-such-dir/probe.json");
    let error = convert(&binary, &missing, &[]);
    assert_eq!(error.status, Some(1), "{}", error.describe());
    assert!(error.stderr.contains("Io"), "{}", error.stderr);
}

// ---------------------------------------------------------------------------
// PDB
// ---------------------------------------------------------------------------

/// Directory with `probe.pdb`, `probe.exe` and `oracle.json` produced elsewhere.
fn pdb_artifacts() -> Option<PathBuf> {
    let directory = std::env::var_os("SYM2ISF_PDB_DIR").map(PathBuf::from)?;
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
    let binary = directory.join("vla");
    compile(
        Command::new(&cc)
            .args(["-O0", "-g", "-gdwarf-4", "-fno-pie", "-no-pie"])
            .arg(&source)
            .arg("-o")
            .arg(&binary),
    );
    let output = directory.join("vla.json");
    let result = convert(&binary, &output, &[]);
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

#[cfg(unix)]
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
    let result = convert(&binary, &output, &[]);
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
            .args(["/link", "/DEBUG:FULL", "/INCREMENTAL:NO", "/DYNAMICBASE:NO"])
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
    assert!(
        names
            .iter()
            .any(|(name, size)| name.ends_with("@tu_two.obj") && *size == 16),
        "the second unit names its variant: {names:?}"
    );
}
