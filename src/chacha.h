#include <stdint.h>

#ifndef __CHACHA_20_H__
#define __CHACHA_20_H__

// manage chacha alg
void chacha_init(uint32_t  out[16]);
void chacha_clear(uint32_t in[16]);

// core algorithm, chacha block
void chacha_block(uint32_t out[16], const uint32_t in[16]);

// cipher
void chacha_xor(uint8_t* out, const uint8_t* in, size_t size, uint32_t ctx[16],
                const uint32_t key[8], const uint32_t nonce[2]);

// hash
void chacha_hash(uint32_t hash[16], uint32_t ctx[16], const uint8_t* message, size_t size);

#endif