# sym2isf

`sym2isf` converts **native DWARF and PDB debug information** into the Ghidra
extended ISF document format.

It is a frontend only: it reads a debug container, normalizes the records it
finds, and writes a JSON (or JSON.XZ) document that other tools consume. It can
also render that document as C declarations — types and function signatures
(`dwarf-c`, `pdb-c`) — or as a LuaJIT FFI module, which is a static memory
layout view: the crate still contains no layout engine, no memory
accessor and no virtual-machine bindings, it never executes or maps the target
program, and it never falls back to Ghidra, a Python script or a downloaded
symbol server.

```
sym2isf dwarf <image> --output <out.json|out.json.xz>
    [--debug-file <path>] [--architecture <arch>] [--types-only]

sym2isf pdb <file.pdb> --output <out.json|out.json.xz>
    [--image <file.exe|file.dll>] [--image-base <decimal|0xhex>] [--types-only]

sym2isf dwarf-c <image> --output <out.c|out.h|out.lua>
    (--type <name> | --function <name>) ... [--all-functions] [--with-addresses]
    [--emit <layout|sdk|ffi>] [--allow-by-value-aggregates]
    [--tcc <executable>] [--luajit <executable>]
    [--debug-file <path>] [--architecture <arch>]

sym2isf pdb-c <file.pdb> --output <out.c|out.h|out.lua>
    (--type <name> | --function <name>) ... [--all-functions] [--with-addresses]
    [--emit <layout|sdk|ffi>] [--allow-by-value-aggregates]
    [--tcc <executable>] [--luajit <executable>]
    [--image <file.exe>] [--image-base <decimal|0xhex>]
```

Exit codes: `0` success, `2` bad arguments, `1` conversion, validation, generation,
compilation or I/O failure. Standard output stays empty on success; the artifact is
the only output of a successful run, and progress or failure is reported on stderr.

`dwarf-c` and `pdb-c` publish the artifact only after an external checker
accepted it: the translation unit is written to a private temporary directory,
compiled with `tcc -Werror -c` (or, for `--emit ffi`, loaded by `--luajit` with
`luajit module.lua`), and only then created at `--output` with `create_new`. The
layout, SDK and FFI views read only the type information unless addresses are
needed; the FFI module needs them only when functions are selected. A missing
checker, a rejected artifact or an existing output leaves no file behind.

## C declarations

`dwarf-c` and `pdb-c` render the selected types and functions, plus every
declaration they need, as one self-contained C translation unit that `tcc -c`
accepts. It is a
*memory layout view*: sizes, offsets and bit-field slices are taken from the
normalized document, never re-derived from an ABI, and the generated code binds no
symbol and calls no target function.

* Plain members keep direct field access. Each aggregate is emitted inside
  `#pragma pack(push, 1)` with explicit byte padding, so no target alignment is
  guessed; `sizeof` and `offsetof` assertions fail the compilation if the document
  and the compiler disagree.
* Bit-fields are not C bit-fields. Each one is stored as the exact recorded byte
  slice and read or written by a generated `static` accessor that touches only the
  bytes the field covers (`bytes[i]` masks and shifts), so the result cannot depend
  on a compiler's bit-field allocation rules.
* Pointer targets that are only pointed at stay forward declarations; typedefs are
  expanded at their use sites and also emitted as `s2c_a_*` aliases.
* Little-endian targets with 4- or 8-byte pointers only. The unit refuses a
  big-endian or unverifiable compiler with `#error`.
* Functions are declared, never bound: `--function` / `--all-functions` emit
  `extern` prototypes. A name C can spell is kept verbatim so a consumer can match
  it against its own declaration; anything else becomes an encoded `s2c_fn_*`
  identifier and a comment keeps the original. Parameter names are kept when the
  document records them and they are legal. `calling_convention` is not emitted as
  an attribute: the unit promises no ABI, and none of this makes the generated
  object export a symbol.
* A function selector reads signatures only, so no address is formed and `pdb-c`
  needs neither `--image` nor `--image-base`; an unlinked `dwarf-c` object works
  too. `--with-addresses` switches to a full conversion and adds a `static const`
  name/address table for the selected functions. That table is data: no
  `address(N)` attribute, no `asm` label, no runtime binding, and a function whose
  record has no address is reported in a comment rather than given one.
* Records that cannot be described (overlapping members, a complete type of size
  zero, a non-native pointer width, a scalar width with no fixed-width C type) fail
  with `CGeneration` and the type or member that caused it; nothing is downgraded
  to a byte blob unless the document already says the unit is opaque.
* Root names are the ISF table keys, so `--type Packet` works for a `struct`
  `Packet` from either frontend. The two frontends are interchangeable: the same
  fixture and the same layout oracle are checked through both `dwarf-c` and
  `pdb-c`.

### SDK view

`--emit sdk` writes a callable header instead of a layout view. Nothing is
linked and nothing is declared for a linker to resolve: the unit carries the
types under their **source** names, one `struct s2c_api` whose members are
function pointers, and a binder that asks **the caller** to resolve each name:

```c
typedef void (*s2c_entry)(void);
typedef s2c_entry (*s2c_resolver)(const char *name, uintptr_t offset);

static inline void s2c_bind(struct s2c_api *api, s2c_resolver resolve)
{
    api->packet_callback =
        (int32_t (*)(Packet *, int32_t)) resolve("packet_callback", (uintptr_t)0x1179ULL);
}
```

* The header never computes an address. `resolve` receives the **source name**
  (the table key, even when the C member had to be encoded) and the recorded
  offset, and returns the address to store; `NULL` leaves the member `NULL`.
  A caller can answer from `dlsym`/`GetProcAddress`, from `module_base + offset`,
  or from a hardcoded table — the generated code is identical.
* The offset is `image_base ? address - image_base : address`, so it is relative
  to the load base for a PDB and already module-relative for a shared object.
  `--emit sdk` always converts with addresses, so a PDB needs `--image` or
  `--image-base`.
* Scalars use the standard fixed-width types (`int32_t`, `uint8_t`, `float`,
  `double`, `uintptr_t`); a character unit keeps a character spelling
  (`char` / `unsigned char`). Aggregates keep their source tags; an enum becomes a
  fixed-width typedef plus its constants; a name C cannot spell falls back to the
  `s2c_*` encoded form. `typedef T T;` tautologies are dropped, and a name the
  includes already define (`int32_t`, `size_t`, the header guard) is never used.
* An explicitly aligned scalar unit is refused: the standard types cannot carry
  the attribute, and dropping it would change the type the header promises.
* An aggregate passed or returned **by value** is refused: the packed layout view
  is not an ABI promise. `--allow-by-value-aggregates` emits it anyway.
* A non-default calling convention on a 32-bit target is refused until the
  attribute is emitted; x86-64 has a single convention and ignores the name.
* `--emit layout` (the default) is unchanged, including `--with-addresses`;
  `--emit ffi` is a separate, purely additive product.

### FFI module

`--emit ffi` writes one Lua module instead of C. It is still declarations, not a
translation unit: the module registers an `ffi.cdef` string, publishes the ctype
of every selected type, and binds callable entries through a resolver the caller
supplies. It never loads a library, never resolves a link name and never
computes an address.

```lua
local M = require("sdk")

M.cdef                                   -- the declarations this module registered
M.types.base_types[name]                 -- ffi.typeof, including a used `void`
M.types.user_types[name]                 -- ffi.typeof; incomplete types allowed
M.types.enums[name]                      -- the fixed-width enum typedef
M.types.typedefs[name]                   -- an alias
M.fields[aggregate][source_member]       -- the cdef identifier of an ordinary member
M.constants[enum][constant]              -- an integer cdata of the enum type
M.bits[aggregate][bit_field].get(p)      -- int64_t/uint64_t cdata
M.bits[aggregate][bit_field].set(p, v)   -- absent for a const bit-field
M.functions[source_function]             -- { member, ctype, offset }
M.api_type                               -- nil when no function was selected
M.bind(resolve)                          -- the filled record; absent without functions
```

* Every table key is the document's own string, byte for byte. A name holding a
  quote, a backslash, a newline, a NUL, non-ASCII text or `]]` stays data: it is
  escaped in Lua and referenced only through a string subscript.
* Type names are always prefixed (`s2c_s_`, `s2c_u_`, `s2c_b_`, `s2c_e_`,
  `s2c_a_`), so an FFI module never occupies a source name in the host ctype
  namespace. Scalars are spelled with the standard fixed-width types, exactly as
  in the SDK view.
* An enum is a fixed-width typedef; its constants are cast to that typedef, never
  carried through a Lua number, so `int64_t` minima and `uint64_t` maxima survive.
* Bit-fields are read and written through the recorded byte slices, never through
  LuaJIT's own allocation rules: a field that starts mid-byte and spans nine bytes
  keeps every neighbouring bit, and a `const` field has no setter.
* `resolve(name, offset)` receives the source name and the recorded offset
  (`image_base ? address - image_base : address`) as `uintptr_t` cdata. It must
  return an address cdata or `nil`; a Lua number or a Lua function is refused,
  because either would lose the address or silently allocate a callback. A `nil`
  answer leaves the member `NULL`, and each call returns a fresh record.
* Selecting a function requires its address, so a PDB needs `--image` or
  `--image-base`; selecting types only does not, so an unlinked object works.
  `--with-addresses` is a layout-view flag and is refused with `--emit ffi`.
* The module refuses to load rather than mislead. Before registering anything it
  checks the byte order, the pointer width and `ffi.arch` against the document
  (`i386`→`x86`, `x86_64`→`x64`, `arm`→`arm`, `aarch64`→`arm64`,
  `powerpc`→`ppc`, `mips`→`mips`/`mipsel`, `mips64`→`mips64`/`mips64el`/
  `mips64r6`/`mips64r6el`); another architecture is refused at generation time.
  It also refuses a name it would define that already exists, because LuaJIT keeps
  an earlier typedef instead of replacing it. After `ffi.cdef` it asserts every
  recorded size, every recorded alignment, the packed alignment it emitted, and
  every member offset.
* The FFI module carries no `extern`, no link name and no `dlsym`: the caller owns
  the module handle, the resolver and the lifetime of everything it returns. The
  target's OS, float ABI and calling convention remain the caller's
  responsibility; the document records none of them, and a 32-bit non-default
  calling convention is refused (top level or nested in a function type) rather
  than silently made the default.
* `--luajit` names the interpreter used to check the module and defaults to
  `luajit` on `PATH`; a relative path resolves against the invoking directory. The
  interpreter must match the target's architecture and pointer width, since that
  is the check. `--tcc` applies to the layout and SDK views only. As with `--tcc`,
  the gate is the named program's exit status: naming something that is not an
  interpreter disables the check, so the product is only as verified as the tool
  you point at.

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

The Linux job carries the extra weight: it builds the probe as a 32-bit image
(`cc -m32`, so `pointer_size`, member offsets and bit-fields are checked on a
second ABI), type-checks the macOS- and Windows-only test paths with
`cargo check --tests --target ...`, and is the formatting/lint gate
(`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`).

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
