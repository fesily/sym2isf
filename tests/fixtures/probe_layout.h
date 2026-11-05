#ifndef PROBE_LAYOUT_H
#define PROBE_LAYOUT_H

#include <stdint.h>

typedef uint32_t word_t;
typedef word_t counter_t;

enum SignedCode { CODE_NEG = -3, CODE_POS = 7 };

struct Node {
    int32_t value;
    struct Node *next;
};

union Value {
    uint32_t word;
    uint8_t bytes[4];
};

struct Bits {
    unsigned int pad : 3;
    signed int field : 5;
    unsigned int tail : 8;
};

#pragma pack(push, 1)
struct Packed {
    uint8_t tag;
    uint32_t value;
};
#pragma pack(pop)

struct Packet {
    int32_t value;
    counter_t counter;
    struct Packet *next;
    struct Node nodes[2];
    union Value payload;
    uint16_t matrix[2][3];
    enum SignedCode code;
    int32_t (*callback)(struct Packet *, int32_t);
};

#endif /* PROBE_LAYOUT_H */
