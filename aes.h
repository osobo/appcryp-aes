#ifndef APPCRYP_AES_H_
#define APPCRYP_AES_H_

#include <stdint.h>

#define KEYSIZE 16
#define ROUNDS 10
#define ROUND_KEYS (ROUNDS+1)
#define ROWS 4
#define COLS 4
#define BLOCKSIZE (ROWS*ROWS)

// Column major!
#define POS(array,i,j) ((array)[(ROWS*(j))+(i)])

typedef unsigned char u8;
typedef unsigned long uint;
typedef uint32_t u32;

void key_sched(u8* roundkeys, const u8* key);

void encrypt_block(u8* block, const u8* roundkeys);
void decrypt_block(u8* block, const u8* roundkeys);

void encrypt(u8* blocks, uint block_count, const u8* key);
void decrypt(u8* blocks, uint block_count, const u8* key);

#endif // APPCRYP_AES_H_
