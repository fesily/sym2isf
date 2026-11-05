/*
 * Freestanding probe for PDB verification.
 *
 * Same types as `probe_layout.h`, but no C runtime calls, so the object can be
 * linked with `lld-link /nodefaultlib` on a machine without the Windows SDK. The
 * Windows CI job links `layout_probe.c` with MSVC and a full runtime instead.
 */

#include "probe_layout.h"

struct Node node_head = {7, 0};
union Value value_global = {0x11223344u};
struct Bits bits_global;
struct Packed packed_global = {0x5a, 0xdeadbeefu};
struct Packet packet_global;
struct Packet *packet_ptr = &packet_global;

static int32_t packet_callback(struct Packet *packet, int32_t delta)
{
    packet->value = packet->value + delta;
    return packet->value;
}

static int32_t add(int32_t left, int32_t right)
{
    return left + right;
}

int main(void)
{
    packet_global.next = &packet_global;
    packet_global.nodes[1].next = &node_head;
    packet_global.payload.word = value_global.word;
    packet_global.matrix[1][2] = 0x55aau;
    packet_global.code = CODE_NEG;
    packet_global.callback = packet_callback;
    bits_global.pad = 5;
    bits_global.field = -3;
    bits_global.tail = 0xa5;
    return add((int32_t)packed_global.tag, packet_global.callback(&packet_global, 1));
}
