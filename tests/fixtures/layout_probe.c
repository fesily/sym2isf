/*
 * Debug-layout probe.
 *
 * Every type from `probe_layout.h` is instantiated in a global object and touched
 * by code so that the compiler keeps its debug information, including the
 * function-pointer signature. The program prints a JSON oracle describing what
 * the compiler actually laid out; the native tests compare that oracle against the
 * ISF document produced by `sym2isf`.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "probe_layout.h"

struct Node node_head = {7, NULL};
union Value value_global = {0x11223344u};
struct Bits bits_global;
struct Packed packed_global = {0x5a, 0xdeadbeefu};
struct Packet packet_global;
struct Packet *packet_ptr = &packet_global;

static int32_t packet_callback(struct Packet *packet, int32_t delta)
{
    packet->value += delta;
    return packet->value;
}

static const char *endian_name(void)
{
    const uint16_t probe = 0x0102u;
    const uint8_t *bytes = (const uint8_t *)&probe;
    return bytes[0] == 0x02u ? "little" : "big";
}

static void print_bits(void)
{
    const uint8_t *bytes = (const uint8_t *)&bits_global;
    size_t index;
    printf("  \"bits_bytes\": \"");
    for (index = 0; index < sizeof(struct Bits); index++) {
        printf("%02x", bytes[index]);
    }
    printf("\",\n");
    printf("  \"bits_values\": {\"pad\": %u, \"field\": %d, \"tail\": %u},\n",
           (unsigned)(bytes[0] & 0x7u) & 0x7u,
           (int)((int8_t)((bytes[0] >> 3) << 3) >> 3),
           (unsigned)bits_global.tail);
}

int main(void)
{
    memset(&packet_global, 0, sizeof(packet_global));
    packet_global.next = &packet_global;
    packet_global.nodes[1].next = &node_head;
    packet_global.payload.word = 0xa1b2c3d4u;
    packet_global.matrix[1][2] = 0x55aau;
    packet_global.code = CODE_NEG;
    packet_global.callback = packet_callback;
    bits_global.pad = 5u;
    bits_global.field = -3;
    bits_global.tail = 0xa5u;

    printf("{\n");
    printf("  \"pointer_size\": %u,\n", (unsigned)sizeof(void *));
    printf("  \"endian\": \"%s\",\n", endian_name());
    printf("  \"sizeof\": {\"Node\": %u, \"Value\": %u, \"Bits\": %u, \"Packed\": %u, \"Packet\": %u},\n",
           (unsigned)sizeof(struct Node), (unsigned)sizeof(union Value),
           (unsigned)sizeof(struct Bits), (unsigned)sizeof(struct Packed),
           (unsigned)sizeof(struct Packet));
    printf("  \"offsetof\": {\"Packet\": {\"value\": %u, \"counter\": %u, \"next\": %u, "
           "\"nodes\": %u, \"payload\": %u, \"matrix\": %u, \"code\": %u, \"callback\": %u}, "
           "\"Packed\": {\"tag\": %u, \"value\": %u}, "
           "\"Node\": {\"value\": %u, \"next\": %u}},\n",
           (unsigned)offsetof(struct Packet, value),
           (unsigned)offsetof(struct Packet, counter),
           (unsigned)offsetof(struct Packet, next),
           (unsigned)offsetof(struct Packet, nodes),
           (unsigned)offsetof(struct Packet, payload),
           (unsigned)offsetof(struct Packet, matrix),
           (unsigned)offsetof(struct Packet, code),
           (unsigned)offsetof(struct Packet, callback),
           (unsigned)offsetof(struct Packed, tag),
           (unsigned)offsetof(struct Packed, value),
           (unsigned)offsetof(struct Node, value),
           (unsigned)offsetof(struct Node, next));
    print_bits();
    printf("  \"address\": {\"packet_global\": %llu, \"node_head\": %llu, "
           "\"value_global\": %llu, \"bits_global\": %llu, \"packed_global\": %llu, "
           "\"packet_ptr\": %llu, \"packet_callback\": %llu},\n",
           (unsigned long long)(uintptr_t)&packet_global,
           (unsigned long long)(uintptr_t)&node_head,
           (unsigned long long)(uintptr_t)&value_global,
           (unsigned long long)(uintptr_t)&bits_global,
           (unsigned long long)(uintptr_t)&packed_global,
           (unsigned long long)(uintptr_t)&packet_ptr,
           (unsigned long long)(uintptr_t)&packet_callback);
    printf("  \"checksum\": %d\n",
           (int)(packet_global.callback(&packet_global, 1) + (int32_t)packet_ptr->value));
    printf("}\n");
    return 0;
}
