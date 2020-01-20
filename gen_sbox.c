#include <stdio.h>
#include <string.h>
#include <assert.h>

typedef unsigned char u8;

u8 rotl(u8 x, int shift) {
    return (u8) (x << shift) | (x >> (8 - shift));
}

// src:
// https://en.wikipedia.org/wiki/Rijndael_S-box#Example_implementation_in_C_language

void gen_box(u8* box) {
    u8 p = 1, q = 1;
    do {
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1b : 0);

        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;

        u8 xformed = q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4);
        box[p] = xformed ^ 0x63;
    } while (p != 1);
    box[0] = 0x63;
}

void invert_box(u8* box) {
    u8 inv[256];
    for (int i = 0; i <= 255; ++i)
        inv[box[i]] = i;
    for (int i = 0; i <= 255; ++i)
        box[i] = inv[i];
}

int main(int argc, char** argv) {
    assert(argc == 2);

    u8 invert;
    if (strcmp(argv[1], "forward") == 0)
        invert = 0;
    else if (strcmp(argv[1], "backward") == 0)
        invert = 1;
    else
        assert(0);

    u8 box[256];
    gen_box(box);

    if (invert) {
        printf("// Generated backward sbox\n");
        invert_box(box);
    } else {
        printf("// Generated forward sbox\n");
    }

    for (int i = 0; i <= 255; ++i) {
        printf("0x%02x, ", box[i]);
        if (i % 16 == 15)
            printf("\n");
    }
}



