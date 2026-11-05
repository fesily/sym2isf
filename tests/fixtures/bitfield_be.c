/*
 * Big-endian bit-field probe.
 *
 * Defines the same bit-field layout as `struct Bits` in `probe_layout.h` without
 * any system header, plus an initialised global, so that a big-endian object can
 * be produced on any host (`clang --target=powerpc64-unknown-linux-gnu -c`) and
 * the emitted ISF bit-field parameters can be checked against the real bytes in
 * that object.
 */

struct Bf {
    unsigned int pad : 3;
    signed int field : 5;
    unsigned int tail : 8;
};

struct Bf bf = {5, -3, 0xA5};
