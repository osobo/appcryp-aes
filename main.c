#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#include "aes.h"

#define MAX_BLOCKS_IN 1000000 // According to Kattis
#define BLOCKS_IN_BUF (MAX_BLOCKS_IN + 1) // +1 for key
#define BUFSIZE (BLOCKS_IN_BUF * BLOCKSIZE)

u8 buf[BUFSIZE];

static inline void kattis_main() {
    uint l = fread(buf, BLOCKSIZE, BLOCKS_IN_BUF, stdin);
    assert(l > 0);
    uint block_count = l - 1;
    u8* key = buf;
    u8* blocks = buf + KEYSIZE;

    encrypt(blocks, block_count, key);

    fwrite(blocks, BLOCKSIZE, block_count, stdout);
}

static inline void flexible_main() {
    uint l;

    u8 key[KEYSIZE];
    l = fread(key, KEYSIZE, 1, stdin);
    assert(l == 1);

    while ((l = fread(buf, BLOCKSIZE, BLOCKS_IN_BUF, stdin)) > 0) {
        uint block_count = l;

        encrypt(buf, block_count, key);
        //decrypt(buf, block_count, key);

        fwrite(buf, BLOCKSIZE, block_count, stdout);
    }
}

int main() {
#ifdef FLEXIBLE
    flexible_main();
#else
    kattis_main();
#endif
}
