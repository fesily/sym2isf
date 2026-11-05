# sym2isf

`sym2isf` converts **native DWARF and PDB debug information** into the Ghidra
extended ISF document format.

It is a frontend only: it reads a debug container, normalizes the records it
finds, and writes a JSON (or JSON.XZ) document that other tools consume. It
contains no layout engine, no memory accessor and no virtual-machine bindings, it
never executes or maps the target program, and it never falls back to Ghidra, a
Python script or a downloaded symbol server.

```
sym2isf dwarf <image> --output <out.json|out.json.xz>
    [--debug-file <path>] [--architecture <arch>] [--types-only]

sym2isf pdb <file.pdb> --output <out.json|out.json.xz>
    [--image <file.exe|file.dll>] [--image-base <decimal|0xhex>] [--types-only]
```

Exit codes: `0` success, `2` bad arguments, `1` conversion, validation or I/O
failure. Standard output stays empty on success; the artifact is the only output
of a successful run, and progress or failure is reported on stderr.

## Output contract

The document always contains, in this order:

```
metadata, base_types, user_types, enums, typedefs, symbols, functions
```

`metadata.format` is `6.2.0`, `metadata.producer` is
`{"name": "sym2isf", "version": "0.1.0"}`. Empty tables are still written, the
key order is fixed and no timestamp or host path is embedded, so converting the
same input twice produces byte-identical output.

References use the Ghidra extended ISF shapes:

| Kind | Shape |
| --- | --- |
| base / struct / union / enum / typedef | `{"kind": "...", "name": "..."}` |
| pointer | `{"kind": "pointer", "subtype": ...}` |
| array | `{"kind": "array", "count": N, "subtype": ...}` |
| bit-field | `{"kind": "bitfield", "bit_length": N, "bit_position": N, "type": ...}` |
| function | `{"kind": "function", "return_type": ..., "parameters": [...]}` |

`metadata.sym2isf` and the members below are **extensions of this producer**, not
stock Ghidra fields:

```json
"metadata": {
  "format": "6.2.0",
  "producer": {"name": "sym2isf", "version": "0.1.0"},
  "sym2isf": {
    "version": 1,
    "target": {"architecture": "x86_64", "pointer_size": 8, "endian": "little"},
    "image_base": 5368709120
  }
}
```

* `target` always comes from the input debug information, never from the host.
* `image_base` is present only when addresses were formed against one (PDB input).
* `alignment` (base and user types) is copied from the debug information and never
  guessed.
* `incomplete: true` marks a type that is only declared; its `size` is `0`.
* `unsupported_reason` appears on `kind: "opaque"` base types, which is how an
  aggregate that cannot be represented statically is published. Every reference to
  it (fields, array elements, pointer targets, typedefs, parameters, return types)
  is rewritten to that base type; there is never a dangling `struct` reference.
* References accept `size` (pointer width override), `qualifiers`
  (`const`/`volatile`/`restrict`) and `reference_kind` (`lvalue`/`rvalue`).
* A bit-field carries `declared_type` (the source type) besides the synthetic
  storage unit in `type`, so normalization never loses the declared type.
* Functions accept `variadic` and `calling_convention`.

### Bit-fields

A bit-field is normalized to the shortest byte slice that covers its bits:

* `offset` is the byte offset of that slice inside the containing aggregate.
* `type` points at a synthetic base unit (`__isf_bits_i<N>` / `__isf_bits_u<N>`)
  whose `size`, signedness and byte order are real.
* `bit_position` counts from the **least significant bit** of the storage unit
  after decoding it with that unit's byte order. For big-endian targets the value
  is flipped so both byte orders share one meaning.

A consumer decodes with a single integer mask, for example:

```text
value = (read_int(offset, size, endian) >> bit_position) & ((1 << bit_length) - 1)
value = sign_extend(value, bit_length)   # when the storage unit is signed
```

Zero-width bit-fields only separate members and are not emitted.

### Naming

* Types keep their source qualified name (`Outer::Inner`).
* Anonymous types become `__anon_dwarf_<section>_<offset>` or
  `__anon_pdb_<type-index>`.
* A type name is not globally unique: its domain is the compilation unit that
  defines it. DWARF keeps a compile-unit name per DIE, and a `.pdb` has no unit on
  the record at all, so there the domain is the module (object file) whose symbols
  use the record. Two units that define `struct Local` with different layouts stay
  two entries, and the domain names the variant: `Local` for the first record and
  `Local@bb.c` / `Local@tu_two.obj` for the others (path-free basenames only).
  Structurally equivalent definitions are merged under one name.
* When no domain distinguishes same-named records, the suffix falls back to
  `__dwarf_<section>_<offset>` / `__pdb_<type-index>`, and a numeric tail keeps it
  unique.
* Synthetic bit-field storage that would collide with a real type name gains a
  `__storage` suffix.

## Failure policy

Nothing is silently dropped:

* Missing or damaged containers, unreadable debug sections, unknown relocations,
  split/supplementary DWARF that was not supplied, an unlinked image without
  `--types-only`, a PDB without an image base, a type the `pdb` crate cannot
  decode, and objects whose layout cannot be represented statically all fail with
  a named error and the record (section offset or type index) that caused it.
* Aggregates that cannot be represented but whose size is known become `opaque`
  base types with a reason; the same for those with an unknown size is an error.
* Forward declarations stay `incomplete` unless a unique complete definition can
  be linked through `DW_AT_specification`/unique name or a unique qualified name.
  Candidates are first narrowed to the declaration's own domain, so a declaration
  in one compilation unit links to that unit's definition.
  Candidate definitions that describe the same layout are the same type and merge;
  candidates that really disagree leave the declaration unresolved, and that
  declaration carries an `unsupported_reason` naming every candidate instead of
  one of them being chosen. Real MSVC PDBs contain such duplicates because the
  same Windows SDK type can be recorded once per translation unit.
* A by-value member whose type is such an unresolved declaration is settled by the
  room the containing record gives it (up to the next member offset, or the end of
  the record): a definition that exactly fills that span is evidence from the debug
  information, not a guess. If no single definition fits, the document is rejected
  as unrepresentable.
* `cl` keeps one record per translation unit, so the module domain separates a
  file-local type in each unit. Clang plus `lld-link` merge the forward-reference
  record of two same-named file-local types into one, which erases the unit from
  the type stream; the two complete layouts are still published separately, but a
  shared forward reference to them can only be resolved by the span rule or stays
  unresolved with its reason.
* A global object whose address is not statically known (TLS, registers, location
  lists) keeps its name and type with `address` omitted; `0` is only ever written
  when the debug information says the address is `0`.

## Known limitations

* Split DWARF (`.dwo`) and supplementary files (`.gnu_debugaltlink`) are detected
  and reported as `MissingDebugCompanion`; they are not loaded implicitly.
* Legacy `.zdebug_*` zlib sections are rejected with an explicit message;
  `SHF_COMPRESSED` sections (`llvm-objcopy --compress-debug-sections=zlib`) are
  read transparently.
* Variable-length arrays and other layouts that need target state at run time
  fail with `UnsupportedLayout` rather than being guessed.
* `pdb` 0.8 rejects some `LF_FIELDLIST` records that Clang pads with zero bytes
  after an `LF_INDEX` continuation. Such an aggregate is published as `opaque`
  with the failing field list index; members are never truncated silently.
* Field-list entries that describe no object layout (nested type declarations,
  methods, member functions, overloaded methods, static members) never become
  members, and they do not degrade the aggregate.
* A pointer whose pointee is a record this crate cannot decode (for example a
  CodeView vtable shape) keeps its own layout and becomes `void*`; the pointee
  identity, not the containment, is what is lost.
* OMAP handling is delegated to `pdb::AddressMap::to_rva`. x86-64 linkers do not
  emit OMAP tables and `llvm-pdbutil yaml2pdb` cannot synthesize them, so that
  branch is exercised only by code review, not by a local fixture.
* The emulated-host claims cover this crate's own code: the library and the binary
  both use `#![forbid(unsafe_code)]`. Third-party crates are not audited here.

## Tests

```
cargo test --locked                       # library, output contract, CLI
SYM2ISF_NATIVE_TESTS=1 \
  cargo test --locked --test native_frontends -- --nocapture
```

The native suite compiles fixtures with the host compiler and converts real
output; `SYM2ISF_NATIVE_TESTS=1` turns a missing compiler or tool into a failure.
The `pdb` cases read a PDB produced elsewhere when `SYM2ISF_PDB_DIR` points at a
directory containing `probe.pdb`, `probe.exe` and `oracle.json`; otherwise they
link a freestanding PDB locally with `clang` plus `lld-link` when those are
available. `.github/workflows/ci.yml` runs the Windows fixture job first and then
parses that same PDB on Linux, macOS and Windows.

In WSL the MSVC toolchain is reachable through interop, so the Windows fixture can
also be produced locally:

```sh
W=/mnt/c/Users/<user>/AppData/Local/Temp/sym2isf-pdb
mkdir -p "$W" && cp tests/fixtures/layout_probe.c tests/fixtures/probe_layout.h "$W/"
cmd.exe /c "cd /d $(wslpath -w "$W") && cl /nologo /Zi /Od /I. /Fdcompile.pdb /Feprobe.exe \
  layout_probe.c /link /DEBUG:FULL /INCREMENTAL:NO /DYNAMICBASE:NO /BASE:0x140000000 \
  /PDB:probe.pdb"
"$W/probe.exe" > "$W/oracle.json"
SYM2ISF_PDB_DIR="$W" SYM2ISF_NATIVE_TESTS=1 cargo test --locked --test native_frontends
```
