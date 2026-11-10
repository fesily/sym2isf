//! LuaJIT FFI rendering of the shared declaration model.
//!
//! The C renderers describe a translation unit; this one describes only what
//! `ffi.cdef` accepts, plus the Lua data a consumer needs: the ctype of every
//! selected type, the cdef identifier of every member, exact bit-field
//! accessors and a binder that asks the caller's resolver for each address.
//!
//! Nothing here loads a library, resolves a link name or computes an address:
//! the recorded offset is handed to the caller's resolver, which owns the module
//! handle and the returned pointers. Type names are always prefixed so the
//! module never takes a source name as a host ctype, and the module refuses to
//! load when it cannot prove the layout it declared.

use std::fmt::Write as _;

use super::*;

/// Append one line to the emitted module.
fn push(out: &mut String, text: &str) {
    out.push_str(text);
    out.push('\n');
}

/// A Lua string literal that keeps every byte of `text`.
///
/// A C literal is wrong here: its octal escapes do not bound the digits, so a
/// name with a NUL followed by a digit would silently change. Every byte outside
/// the printable ASCII range becomes a fixed three-digit decimal escape instead.
fn lua_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for byte in text.bytes() {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(byte as char),
            other => {
                let _ = write!(out, "\\{other:03}");
            }
        }
    }
    out.push('"');
    out
}

/// The shortest Lua long bracket whose closing sequence the text cannot end.
///
/// A name in a comment may contain `]]` or `]===]`; taking the first level the
/// text does not close keeps the module parseable without escaping the cdef.
fn lua_long_bracket(text: &str) -> String {
    let mut level = 0usize;
    loop {
        let equals = "=".repeat(level);
        let close = format!("]{equals}]");
        // A text that ends with the opening part of the close sequence ends the
        // string early even though it does not contain the whole sequence.
        let open_tail = format!("]{equals}");
        if !text.contains(&close) && !text.ends_with(&open_tail) {
            return format!("[{equals}[{text}]{equals}]");
        }
        level += 1;
    }
}

/// One line of Lua comment text: a control byte would end the comment.
fn lua_comment(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

/// The `ffi.arch` names a target architecture may report.
///
/// The target record carries no OS, float ABI or endianness beyond `Endian`; a
/// name outside this table is refused rather than guessed.
fn lua_arch_names(architecture: &str) -> Option<&'static [&'static str]> {
    let names: &'static [&'static str] = match architecture {
        "i386" => &["x86"],
        "x86_64" => &["x64"],
        "arm" => &["arm"],
        "aarch64" => &["arm64"],
        "powerpc" => &["ppc"],
        "mips" => &["mips", "mipsel"],
        "mips64" => &["mips64", "mips64el", "mips64r6", "mips64r6el"],
        _ => return None,
    };
    Some(names)
}

/// The Lua declarations and data for one prepared generator.
pub(super) fn emit(mut generator: Generator<'_>) -> Result<String> {
    let target = generator.doc.metadata.sym2isf.target.clone();
    let architecture = &target.architecture;
    let pointer_size = target.pointer_size;
    let names = lua_arch_names(architecture).ok_or_else(|| {
        cg(
            &Loc::Roots,
            format!("target architecture `{architecture}` has no LuaJIT FFI name mapping"),
        )
    })?;

    // -----------------------------------------------------------------------
    // Declarations
    // -----------------------------------------------------------------------

    let mut cdef = String::new();
    line(
        &mut cdef,
        format_args!("/* sym2isf LuaJIT FFI declarations; not a translation unit */"),
    );
    line(
        &mut cdef,
        format_args!(
            "/* target: little endian, {pointer_size}-byte pointers; packed layout, no ABI promise */"
        ),
    );
    blank(&mut cdef);
    generator.emit_forwards(&mut cdef);
    generator.emit_base_units(&mut cdef)?;
    generator.emit_enums(&mut cdef, false)?;
    blank(&mut cdef);
    generator.emit_aggregates(&mut cdef)?;
    generator.emit_aliases(&mut cdef)?;

    let (api_record, members): (Option<String>, Vec<ApiMember>) = if generator.functions.is_empty()
    {
        (None, Vec::new())
    } else {
        let members = generator.api_members()?;
        let record = generator.emit_api_record(&mut cdef, &members);
        (Some(record), members)
    };

    // -----------------------------------------------------------------------
    // Names the module owns, and the layout it must prove
    // -----------------------------------------------------------------------

    let mut typedefs: Vec<String> = Vec::new();
    for name in &generator.used.scalars {
        if let Some(identifier) = generator.base_names.get(name) {
            typedefs.push(identifier.clone());
        }
    }
    let mut aggregates: Vec<String> = generator
        .used
        .declared
        .iter()
        .chain(generator.used.complete.iter())
        .cloned()
        .collect();
    aggregates.sort();
    aggregates.dedup();
    for name in &aggregates {
        typedefs.push(generator.aggregate_names[name].clone());
    }
    for name in &generator.used.enums {
        typedefs.push(generator.enum_names[name].clone());
    }
    for name in &generator.used.aliases {
        typedefs.push(generator.alias_names[name].clone());
    }
    if let Some(record) = &api_record {
        typedefs.push(record.clone());
    }

    // A named tag is not a typedef, and `ffi.typeof` reports both: probe each
    // form the module would define.
    let mut tags: Vec<String> = Vec::new();
    for name in &aggregates {
        let keyword = match generator.doc.user_types[name].kind {
            CompositeKind::Struct => "struct",
            CompositeKind::Union => "union",
        };
        tags.push(format!("{keyword} {}", generator.aggregate_names[name]));
    }
    for name in &generator.used.scalars {
        if generator.doc.base_types[name].kind == BaseKind::Opaque {
            if let Some(identifier) = generator.base_names.get(name) {
                tags.push(format!("struct {identifier}"));
            }
        }
    }
    // The record is defined as `struct <record> { … }` before its typedef, so
    // the tag is a separate name a host may already have declared.
    if let Some(record) = &api_record {
        tags.push(format!("struct {record}"));
    }

    // -----------------------------------------------------------------------
    // Module: target checks, name probes, cdef, layout assertions, data
    // -----------------------------------------------------------------------

    let mut out = String::new();
    push(
        &mut out,
        "-- generated by sym2isf: LuaJIT FFI view of an extended ISF document",
    );
    push(
        &mut out,
        &format!(
            "-- target {}: little endian, {pointer_size}-byte pointers",
            lua_comment(architecture)
        ),
    );
    push(
        &mut out,
        "-- declarations only: no library is loaded and no address is computed here",
    );
    push(&mut out, "");
    push(&mut out, "local ffi = require(\"ffi\")");

    let has_bitfields = generator
        .order
        .iter()
        .any(|name| !generator.layouts[name].bitfields.is_empty());
    if has_bitfields {
        push(&mut out, "local bit = require(\"bit\")");
    }
    push(&mut out, "");

    push(&mut out, "if not ffi.abi(\"le\") then");
    push(
        &mut out,
        &format!(
            "  error({}, 0)",
            lua_string(
                "s2c: byte order mismatch: declarations target little endian, this LuaJIT is big endian"
            )
        ),
    );
    push(&mut out, "end");
    push(
        &mut out,
        &format!("if ffi.sizeof(\"void *\") ~= {pointer_size} then"),
    );
    push(
        &mut out,
        &format!(
            "  error({} .. tostring(ffi.sizeof(\"void *\")) .. {}, 0)",
            lua_string(&format!(
                "s2c: pointer width mismatch: declarations target {pointer_size}-byte pointers, this LuaJIT has "
            )),
            lua_string("-byte pointers")
        ),
    );
    push(&mut out, "end");
    // The interpreter must describe the same machine the document came from.
    let arch_names = names
        .iter()
        .map(|name| format!("ffi.arch == {}", lua_string(name)))
        .collect::<Vec<String>>();
    let arch_mismatch = if arch_names.len() == 1 {
        format!("ffi.arch ~= {}", lua_string(names[0]))
    } else {
        format!("not ({})", arch_names.join(" or "))
    };
    push(&mut out, &format!("if {arch_mismatch} then"));
    push(
        &mut out,
        &format!(
            "  error({} .. tostring(ffi.arch), 0)",
            lua_string(&format!(
                "s2c: architecture mismatch: declarations target {architecture}, this LuaJIT is "
            ))
        ),
    );
    push(&mut out, "end");
    push(&mut out, "");

    // Registering twice would silently validate against the earlier definition:
    // LuaJIT keeps a conflicting typedef instead of replacing it.
    push(
        &mut out,
        "-- A name this module defines must not exist yet: a rejected or repeated",
    );
    push(
        &mut out,
        "-- declaration would otherwise be checked against a different definition.",
    );
    push(&mut out, "local OWNED = {");
    for name in &typedefs {
        push(&mut out, &format!("  {},", lua_string(name)));
    }
    push(&mut out, "}");
    push(&mut out, "local OWNED_TAGS = {");
    for tag in &tags {
        push(&mut out, &format!("  {},", lua_string(tag)));
    }
    push(&mut out, "}");
    push(&mut out, "for i = 1, #OWNED_TAGS do");
    push(&mut out, "  if pcall(ffi.typeof, OWNED_TAGS[i]) then");
    push(
        &mut out,
        "    error(\"s2c: ctype already defined: \" .. OWNED_TAGS[i], 0)",
    );
    push(&mut out, "  end");
    push(&mut out, "end");
    push(&mut out, "for i = 1, #OWNED do");
    push(&mut out, "  if pcall(ffi.typeof, OWNED[i]) then");
    push(
        &mut out,
        "    error(\"s2c: ctype already defined: \" .. OWNED[i], 0)",
    );
    push(&mut out, "  end");
    push(&mut out, "end");
    push(&mut out, "");

    push(
        &mut out,
        &format!("local CDEF = {}", lua_long_bracket(&cdef)),
    );
    push(&mut out, "ffi.cdef(CDEF)");
    push(&mut out, "");

    for assertion in layout_assertions(&generator)? {
        push(&mut out, &assertion);
    }
    push(&mut out, "");

    // -----------------------------------------------------------------------
    // Data tables
    // -----------------------------------------------------------------------

    push(&mut out, "local M = {}");
    push(&mut out, "M.cdef = CDEF");
    push(
        &mut out,
        "M.types = { base_types = {}, user_types = {}, enums = {}, typedefs = {} }",
    );
    for name in &generator.used.scalars {
        let spelling = base_spelling(&generator, name)?;
        push(
            &mut out,
            &format!(
                "M.types.base_types[{}] = ffi.typeof({})",
                lua_string(name),
                lua_string(&spelling)
            ),
        );
    }
    for name in &aggregates {
        push(
            &mut out,
            &format!(
                "M.types.user_types[{}] = ffi.typeof({})",
                lua_string(name),
                lua_string(&generator.aggregate_names[name])
            ),
        );
    }
    for name in &generator.used.enums {
        push(
            &mut out,
            &format!(
                "M.types.enums[{}] = ffi.typeof({})",
                lua_string(name),
                lua_string(&generator.enum_names[name])
            ),
        );
    }
    for name in &generator.used.aliases {
        push(
            &mut out,
            &format!(
                "M.types.typedefs[{}] = ffi.typeof({})",
                lua_string(name),
                lua_string(&generator.alias_names[name])
            ),
        );
    }
    push(&mut out, "");

    push(&mut out, "M.fields = {}");
    for name in &generator.order {
        let mut entries: Vec<String> = Vec::new();
        for member in &generator.layouts[name].members {
            if !matches!(member.kind, MemberKind::Ordinary(_)) {
                continue;
            }
            let Some(origin) = &member.origin else {
                continue;
            };
            entries.push(format!(
                "  [{}] = {},",
                lua_string(origin),
                lua_string(&member.identifier)
            ));
        }
        if entries.is_empty() {
            push(&mut out, &format!("M.fields[{}] = {{}}", lua_string(name)));
        } else {
            push(&mut out, &format!("M.fields[{}] = {{", lua_string(name)));
            for entry in entries {
                push(&mut out, &entry);
            }
            push(&mut out, "}");
        }
    }
    push(&mut out, "");

    push(&mut out, "M.constants = {}");
    for name in &generator.used.enums {
        let identifier = &generator.enum_names[name];
        let constants = &generator.doc.enums[name].constants;
        if constants.is_empty() {
            push(
                &mut out,
                &format!("M.constants[{}] = {{}}", lua_string(name)),
            );
            continue;
        }
        push(&mut out, &format!("M.constants[{}] = {{", lua_string(name)));
        for (constant, value) in constants {
            // The 64-bit literal is cast to the enum typedef, never carried
            // through a Lua number.
            push(
                &mut out,
                &format!(
                    "  [{}] = ffi.cast({}, {}),",
                    lua_string(constant),
                    lua_string(identifier),
                    enum_literal(*value)
                ),
            );
        }
        push(&mut out, "}");
    }
    push(&mut out, "");

    push(&mut out, "M.bits = {}");
    for name in &generator.order {
        let layout = &generator.layouts[name];
        if layout.bitfields.is_empty() {
            continue;
        }
        push(&mut out, &format!("M.bits[{}] = {{}}", lua_string(name)));
        for bitfield in &layout.bitfields {
            emit_bitfield(&mut out, name, bitfield);
        }
    }
    push(&mut out, "");

    push(&mut out, "M.functions = {}");
    // The record exists exactly when functions were selected, and then the
    // described list is non-empty.
    if let Some(record) = &api_record {
        for member in &members {
            push(
                &mut out,
                &format!(
                    "M.functions[{}] = {{ member = {}, ctype = ffi.typeof({}), offset = {} }}",
                    lua_string(&member.source),
                    lua_string(&member.identifier),
                    lua_string(&member.cast),
                    offset_literal(member.rva, pointer_size)
                ),
            );
        }
        push(&mut out, "");
        push(
            &mut out,
            &format!("M.api_type = ffi.typeof({})", lua_string(record)),
        );
        // One ordered list and one loop: a module selected with --all-functions
        // must not create a local variable per entry.
        push(&mut out, "local DESCRIBED = {");
        for member in &members {
            push(
                &mut out,
                &format!(
                    "  {{ name = {}, member = {}, ctype = ffi.typeof({}), offset = {} }},",
                    lua_string(&member.source),
                    lua_string(&member.identifier),
                    lua_string(&member.cast),
                    offset_literal(member.rva, pointer_size)
                ),
            );
        }
        push(&mut out, "}");
        push(&mut out, "");
        push(
            &mut out,
            "-- The caller owns every address: a nil result leaves the member NULL.",
        );
        push(&mut out, "function M.bind(resolve)");
        push(&mut out, "  local api = M.api_type()");
        push(&mut out, "  for i = 1, #DESCRIBED do");
        push(&mut out, "    local described = DESCRIBED[i]");
        push(
            &mut out,
            "    local address = resolve(described.name, described.offset)",
        );
        push(&mut out, "    if address ~= nil then");
        push(&mut out, "      if type(address) ~= \"cdata\" then");
        push(
            &mut out,
            "        error(\"s2c: resolver must return address cdata or nil\", 0)",
        );
        push(&mut out, "      end");
        push(
            &mut out,
            "      api[described.member] = ffi.cast(described.ctype, address)",
        );
        push(&mut out, "    end");
        push(&mut out, "  end");
        push(&mut out, "  return api");
        push(&mut out, "end");
    }
    push(&mut out, "");
    push(&mut out, "return M");

    Ok(out)
}

/// `uintptr_t` cdata for one recorded offset.
fn offset_literal(rva: u64, pointer_size: u64) -> String {
    let digits = if pointer_size == 4 { 8 } else { 16 };
    format!("ffi.cast(\"uintptr_t\", 0x{rva:0digits$x}ULL)")
}

/// The cdef spelling of one `base_types` entry.
fn base_spelling(generator: &Generator<'_>, name: &str) -> Result<String> {
    let base = &generator.doc.base_types[name];
    if base.kind == BaseKind::Void {
        return Ok("void".to_string());
    }
    if base.kind == BaseKind::Opaque {
        return generator
            .base_names
            .get(name)
            .cloned()
            .ok_or_else(|| cg(&Loc::Type(name), "opaque base type was not declared"));
    }
    generator.sdk_scalar(base, name)
}

/// The size, alignment and member-offset checks the module runs after `cdef`.
fn layout_assertions(generator: &Generator<'_>) -> Result<Vec<String>> {
    let mut assertions: Vec<String> = Vec::new();
    for name in &generator.used.scalars {
        let base = &generator.doc.base_types[name];
        // An incomplete type has no size to check.
        if base.kind == BaseKind::Void {
            continue;
        }
        let spelling = base_spelling(generator, name)?;
        assertions.push(format!(
            "assert(ffi.sizeof({}) == {}, {})",
            lua_string(&spelling),
            base.size,
            lua_string(&format!("s2c: sizeof({spelling}) != {}", base.size))
        ));
        if let Some(alignment) = check_alignment(base.alignment, base.size, name)? {
            assertions.push(format!(
                "assert(ffi.alignof({}) == {alignment}, {})",
                lua_string(&spelling),
                lua_string(&format!("s2c: alignof({spelling}) != {alignment}"))
            ));
        }
    }
    for name in &generator.used.enums {
        let identifier = &generator.enum_names[name];
        let size = generator.doc.enums[name].size;
        assertions.push(format!(
            "assert(ffi.sizeof({}) == {size}, {})",
            lua_string(identifier),
            lua_string(&format!("s2c: sizeof({identifier}) != {size}"))
        ));
    }
    for name in &generator.order {
        let layout = &generator.layouts[name];
        let identifier = &generator.aggregate_names[name];
        assertions.push(format!(
            "assert(ffi.sizeof({}) == {}, {})",
            lua_string(identifier),
            layout.size,
            lua_string(&format!("s2c: sizeof({identifier}) != {}", layout.size))
        ));
        // Without a recorded alignment the only claim the module can check is
        // the packed one it emitted; it does not claim the target's natural
        // alignment.
        let alignment = layout.alignment.unwrap_or(1);
        assertions.push(format!(
            "assert(ffi.alignof({}) == {alignment}, {})",
            lua_string(identifier),
            lua_string(&format!("s2c: alignof({identifier}) != {alignment}"))
        ));
        for member in &layout.members {
            if matches!(member.kind, MemberKind::Pad) {
                continue;
            }
            assertions.push(format!(
                "assert(ffi.offsetof({}, {}) == {}, {})",
                lua_string(identifier),
                lua_string(&member.identifier),
                member.offset,
                lua_string(&format!(
                    "s2c: offsetof({identifier}, {}) != {}",
                    member.identifier, member.offset
                ))
            ));
        }
    }
    Ok(assertions)
}

/// One exact bit-field accessor pair.
///
/// The generated functions read and write the recorded byte slices, so they
/// depend on neither the compiler's bit-field allocation rules nor a 32-bit
/// shift; the value that crosses the boundary is always a 64-bit integer cdata.
fn emit_bitfield(out: &mut String, aggregate: &str, bitfield: &BitfieldLayout) {
    let width = bitfield.bit_length;
    let mask = if width >= 64 {
        "0xffffffffffffffffULL".to_string()
    } else {
        format!("0x{:016x}ULL", (1u64 << width) - 1)
    };
    let chunks = bitfield_chunks(bitfield);
    push(
        out,
        &format!(
            "M.bits[{}][{}] = {{",
            lua_string(aggregate),
            lua_string(&bitfield.field)
        ),
    );
    push(out, "  get = function(p)");
    push(out, "    local bytes = ffi.cast(\"uint8_t *\", p)");
    push(out, "    local u = 0ULL");
    for chunk in &chunks {
        let piece = if chunk.lo == 0 {
            format!("bit.band(bytes[{}], 0x{:02x})", chunk.byte, chunk.byte_mask)
        } else {
            format!(
                "bit.band(bit.rshift(bytes[{}], {}), 0x{:02x})",
                chunk.byte, chunk.lo, chunk.byte_mask
            )
        };
        push(
            out,
            &format!(
                "    u = bit.bor(u, bit.lshift(ffi.cast(\"uint64_t\", {piece}), {}))",
                chunk.u_shift
            ),
        );
    }
    if bitfield.signed {
        if width >= 64 {
            push(out, "    return ffi.cast(\"int64_t\", u)");
        } else {
            let shift = 64 - width;
            push(
                out,
                &format!(
                    "    return bit.arshift(ffi.cast(\"int64_t\", bit.lshift(u, {shift})), {shift})"
                ),
            );
        }
    } else {
        push(out, "    return u");
    }
    push(out, "  end,");
    if bitfield.is_const {
        // A const field has no setter; the module never writes it.
        push(out, "}");
        return;
    }
    push(out, "  set = function(p, value)");
    // A Lua number is not a 64-bit integer: converting a negative one directly
    // would saturate instead of wrapping, so it goes through `int64_t` first.
    push(out, "    if type(value) == \"number\" and value < 0 then");
    push(out, "      value = ffi.cast(\"int64_t\", value)");
    push(out, "    end");
    push(
        out,
        &format!("    local u = bit.band(ffi.cast(\"uint64_t\", value), {mask})"),
    );
    push(out, "    local bytes = ffi.cast(\"uint8_t *\", p)");
    for chunk in &chunks {
        let keep = !(chunk.byte_mask << chunk.lo) & 0xff;
        push(
            out,
            &format!(
                "    bytes[{}] = tonumber(bit.bor(ffi.cast(\"uint64_t\", bit.band(bytes[{}], 0x{keep:02x})), bit.lshift(bit.band(bit.rshift(u, {}), 0x{:02x}), {})))",
                chunk.byte, chunk.byte, chunk.u_shift, chunk.byte_mask, chunk.lo
            ),
        );
    }
    push(out, "  end,");
    push(out, "}");
}
