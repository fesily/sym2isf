/*
 * C++ layout probe: virtual bases, non-virtual bases and forward declarations.
 *
 * GCC and Clang record a virtual base without any static member offset, so the
 * whole affected class has to be emitted as an opaque unit, while non-virtual
 * bases keep a real offset and become `__base_<n>` members.
 */

struct Base {
    int b;
};

struct DerivedVirtual : virtual Base {
    int x;
};

struct PlainBase {
    int p;
};

struct Plain : PlainBase {
    int q;
};

struct Fwd;

// Used before it is defined: the definition is linked through the declaration
// record `DW_AT_specification`.
struct Later;

struct Holder {
    Fwd *ptr;
    Later *later;
};

struct Later {
    int value;
    int extra;
};

struct Later later_global;
DerivedVirtual derived_virtual_global;
Plain plain_global;
PlainBase plain_base_global;
Base base_global;
Holder holder_global;
Fwd *fwd_global = 0;

int main()
{
    derived_virtual_global.x = 3;
    plain_global.p = 1;
    plain_global.q = 2;
    plain_base_global.p = 4;
    base_global.b = 5;
    holder_global.ptr = fwd_global;
    holder_global.later = &later_global;
    later_global.value = 6;
    later_global.extra = 7;
    return derived_virtual_global.x + plain_global.p + plain_global.q + base_global.b
        + later_global.value + later_global.extra;
}
