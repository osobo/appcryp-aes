#include <string.h>
#include <assert.h>
#include <time.h>

#include "aes.h"

// src: https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
// 1-indexed, 1,2,...,10
static inline u8 rc(u8 i) {
    static const u8 arr[] = {
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1b, 0x36
    };
    return arr[i-1];
}

// src: https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
static inline u32 rcon(u8 i) {
    u32 w = 0;
    ((u8*)&w)[0] = rc(i);
    return w;
}

// src: https://en.wikipedia.org/wiki/Rijndael_S-box
static inline u8 sub(u8 x) {
    static const u8 arr[] = {
        #include "sbox_forward.inc"
    };
    return arr[x];
}

static inline u32 subword(u32 x) {
    u8* bs = (u8*) &x;
    bs[0] = sub(bs[0]);
    bs[1] = sub(bs[1]);
    bs[2] = sub(bs[2]);
    bs[3] = sub(bs[3]);
    return x;
}

static inline u32 rot(u32 b) {
    u8* bs = (u8*) &b;
    u8 b0 = bs[0];
    bs[0] = bs[1];
    bs[1] = bs[2];
    bs[2] = bs[3];
    bs[3] = b0;
    return b;
}

// src: https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
void key_sched(u8* roundkeys, const u8* key) {
    static const uint N = 4; // Number of 32-bit words in 128 bit key
    static const uint R = ROUND_KEYS;

    const u32* keywords= (u32*) key;
    u32* roundkeywords= (u32*) roundkeys;

    for (uint i = 0; i < 4*R; ++i) {
        u32 w;
        if (i < N) {
            w = keywords[i];
        } else {
            u32 w1 = roundkeywords[i-1];
            u32 wn = roundkeywords[i-N];
            if (i % N == 0)
                w = wn ^ subword(rot(w1)) ^ rcon(i/N);
            else if (N>6 && i % N == 4)
                w = wn ^ subword(w1);
            else
                w = wn ^ w1;
        }
        roundkeywords[i] = w;
    }
}

// src: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_AddRoundKey_step
static inline void add_round_key(u8* block,
                                 const u8* roundkeys,
                                 uint i)
{
    ((uint64_t*)block)[0] ^= ((uint64_t*)(roundkeys + (i*BLOCKSIZE)))[0];
    ((uint64_t*)block)[1] ^= ((uint64_t*)(roundkeys + (i*BLOCKSIZE)))[1];
}

// src: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_SubBytes_step
static inline void sub_bytes(u8* block) {
    for (uint j = 0; j < BLOCKSIZE; ++j)
        block[j] = sub(block[j]);
}

// src: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step
static inline void shift_rows(u8* block) {
    u8 x;

    // Row 0 doesn't change

    // Row 1
    x = POS(block,1,0);
    POS(block,1,0) = POS(block,1,1);
    POS(block,1,1) = POS(block,1,2);
    POS(block,1,2) = POS(block,1,3);
    POS(block,1,3) = x;

    // Row 2
    x = POS(block,2,0);
    POS(block,2,0) = POS(block,2,2);
    POS(block,2,2) = x;
    x = POS(block,2,1);
    POS(block,2,1) = POS(block,2,3);
    POS(block,2,3) = x;

    // Row 3
    x = POS(block,3,3);
    POS(block,3,3) = POS(block,3,2);
    POS(block,3,2) = POS(block,3,1);
    POS(block,3,1) = POS(block,3,0);
    POS(block,3,0) = x;
}


// src: https://en.wikipedia.org/wiki/Rijndael_MixColumns
static inline void mix_column(u8* block, uint j) {
    static u8 two[256] = {
        #include "mult2.inc"
    };
    static u8 three[256] = {
        #include "mult3.inc"
    };
    u8 a[4] = {
        POS(block,0,j), POS(block,1,j), POS(block,2,j), POS(block,3,j)
    };

    // (2, 3, 1, 1) . a
    POS(block,0,j) = two[a[0]]   ^ three[a[1]] ^ a[2]        ^ a[3];
    // (1, 2, 3, 1) . a
    POS(block,1,j) = a[0]        ^ two[a[1]]   ^ three[a[2]] ^ a[3];
    // (1, 1, 2, 3) . a
    POS(block,2,j) = a[0]        ^ a[1]        ^ two[a[2]]   ^ three[a[3]];
    // (3, 1, 1, 2) . a
    POS(block,3,j) = three[a[0]] ^ a[1]        ^ a[2]        ^ two[a[3]];
}

static inline void mix_columns(u8* block) {
    mix_column(block, 0);
    mix_column(block, 1);
    mix_column(block, 2);
    mix_column(block, 3);
}

// src: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#High-level_description_of_the_algorithm
void encrypt_block(u8* block, const u8* roundkeys) {
    uint round = 0;

    // Initial AddRoundKey
    add_round_key(block, roundkeys, round);

    // All but last round
    for (round = 1; round <= ROUNDS-1; ++round) {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, roundkeys, round);
    }

    // Last round
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, roundkeys, round);
}

void encrypt(u8* blocks, uint block_count, const u8* key) {
    u8 roundkeys[ROUND_KEYS*BLOCKSIZE];
    key_sched(roundkeys, key);
    for (uint i = 0; i < block_count; ++i)
        encrypt_block(blocks+(BLOCKSIZE*i), roundkeys);
}

#ifdef DECRYPT

// src: https://en.wikipedia.org/wiki/Rijndael_S-box
static inline u8 sub_inv(u8 x) {
    static const u8 arr[] = {
        #include "sbox_backward.inc"
    };
    return arr[x];
}


static inline u32 subword_inv(u32 x) {
    u8* bs = (u8*) &x;
    bs[0] = sub_inv(bs[0]);
    bs[1] = sub_inv(bs[1]);
    bs[2] = sub_inv(bs[2]);
    bs[3] = sub_inv(bs[3]);
    return x;
}

// src: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_SubBytes_step
static inline void sub_bytes_inv(u8* block) {
    for (uint j = 0; j < BLOCKSIZE; ++j)
        block[j] = sub_inv(block[j]);
}


// src: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step
static inline void shift_rows_inv(u8* block) {
    u8 x;

    // Row 0 doesn't change

    // Row 1 (like row 3)
    x = POS(block,1,3);
    POS(block,1,3) = POS(block,1,2);
    POS(block,1,2) = POS(block,1,1);
    POS(block,1,1) = POS(block,1,0);
    POS(block,1,0) = x;

    // Row 2 (same)
    x = POS(block,2,0);
    POS(block,2,0) = POS(block,2,2);
    POS(block,2,2) = x;
    x = POS(block,2,1);
    POS(block,2,1) = POS(block,2,3);
    POS(block,2,3) = x;

    // Row 3 (like row 1)
    x = POS(block,3,0);
    POS(block,3,0) = POS(block,3,1);
    POS(block,3,1) = POS(block,3,2);
    POS(block,3,2) = POS(block,3,3);
    POS(block,3,3) = x;
}

// src: https://en.wikipedia.org/wiki/Rijndael_MixColumns
static inline void mix_column_inv(u8* block, uint j) {
    static u8 m9[256] = {
        #include "mult9.inc"
    };
    static u8 m11[256] = {
        #include "mult11.inc"
    };
    static u8 m13[256] = {
        #include "mult13.inc"
    };
    static u8 m14[256] = {
        #include "mult14.inc"
    };
    u8 a[4] = {
        POS(block,0,j), POS(block,1,j), POS(block,2,j), POS(block,3,j)
    };

    // (14, 11, 13, 9) . a
    // (9, 14, 11, 13) . a
    // (13, 9, 14, 11) . a
    // (11, 13, 9, 14) . a

    POS(block,0,j) = m14[a[0]] ^ m11[a[1]] ^ m13[a[2]] ^ m9[a[3]];
    POS(block,1,j) = m9[a[0]]  ^ m14[a[1]] ^ m11[a[2]] ^ m13[a[3]];
    POS(block,2,j) = m13[a[0]] ^ m9[a[1]]  ^ m14[a[2]] ^ m11[a[3]];
    POS(block,3,j) = m11[a[0]] ^ m13[a[1]] ^ m9[a[2]]  ^ m14[a[3]];
}

static inline void mix_columns_inv(u8* block) {
    mix_column_inv(block, 0);
    mix_column_inv(block, 1);
    mix_column_inv(block, 2);
    mix_column_inv(block, 3);
}

// src: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#High-level_description_of_the_algorithm
void decrypt_block(u8* block, const u8* roundkeys) {
    // Invert last round
    add_round_key(block, roundkeys, ROUND_KEYS-1);
    shift_rows_inv(block);
    sub_bytes_inv(block);

    // Invert rest except initial roundkey
    for (uint round = ROUNDS-1; round >= 1; --round) {
        add_round_key(block, roundkeys, round);
        mix_columns_inv(block);
        shift_rows_inv(block);
        sub_bytes_inv(block);
    }

    // Invert initial roundkey
    add_round_key(block, roundkeys, 0);
}

void decrypt(u8* blocks, uint block_count, const u8* key) {
    u8 roundkeys[ROUND_KEYS*BLOCKSIZE];
    key_sched(roundkeys, key);
    for (uint i = 0; i < block_count; ++i)
        decrypt_block(blocks+(BLOCKSIZE*i), roundkeys);
}

#endif // DECRYPT
