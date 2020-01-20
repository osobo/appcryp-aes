#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

typedef unsigned char u8;

// src: https://en.wikipedia.org/wiki/Rijndael_Galois_field#Multiplication
// Galois Field (256) Multiplication of two Bytes
u8 gal_mul(u8 a, u8 b) {
    u8 p = 0;
    for (int ctr = 0; ctr < 8; ++ctr) {
        if ((b & 1) != 0)
            p ^= a;

        // Mult a by two in same way as b-vec i calc in mix column
        int hi_set = (a & 0x80) != 0;
        a <<= 1;
        if (hi_set)
            a ^= 0x1b;

        b >>= 1;
    }
    return p;
}

int main(int argc, char** argv) {
    assert(argc == 2);
    int i;
    int res = sscanf(argv[1], "%d", &i);
    assert(res == 1 && i >= 0 && i <= 255);
    u8 cof = i;
    printf("// Generated multiplication table for %u = 0x%02x\n", cof, cof);
    for (int x = 0; x <= 255; ++x) {
        u8 y = gal_mul(cof, x);
        printf("0x%02x, ", y);
        if (x % 16 == 15)
            printf("\n");
    }
}
