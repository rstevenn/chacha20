#include <stdint.h>
#include <stdio.h>
#include "chacha.h"

// utils macro
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) (			\
	a += b,  d ^= a,  d = ROTL(d,16),	\
	c += d,  b ^= c,  b = ROTL(b,12),	\
	a += b,  d ^= a,  d = ROTL(d, 8),	\
	c += d,  b ^= c,  b = ROTL(b, 7))
#define ROUNDS 20
 
// impl
void chacha_block(uint32_t out[16], const uint32_t in[16])
{
	int i;
	uint32_t x[16];

	for (i = 0; i < 16; ++i)	
		x[i] = in[i];
	// 10 loops × 2 rounds/loop = 20 rounds
	for (i = 0; i < ROUNDS; i += 2) {
		// Odd round
		QR(x[0], x[4], x[ 8], x[12]); // column 0
		QR(x[1], x[5], x[ 9], x[13]); // column 1
		QR(x[2], x[6], x[10], x[14]); // column 2
		QR(x[3], x[7], x[11], x[15]); // column 3
		// Even round
		QR(x[0], x[5], x[10], x[15]); // diagonal 1 (main diagonal)
		QR(x[1], x[6], x[11], x[12]); // diagonal 2
		QR(x[2], x[7], x[ 8], x[13]); // diagonal 3
		QR(x[3], x[4], x[ 9], x[14]); // diagonal 4
	}
	for (i = 0; i < 16; ++i)
		out[i] = x[i] + in[i];
    
    // clear x
    for (i=0; i<16; i++)
        x[i] = 0;
}

void chacha_init(uint32_t out[16]) {
    for (size_t i=0; i<16; i++)
        out[i] = 0;

    out[0] = *(uint32_t*)"expa";
    out[1] = *(uint32_t*)"nb 3";
    out[2] = *(uint32_t*)"2-by";
    out[3] = *(uint32_t*)"te k";
}

void chacha_clear(uint32_t in[16]) {
    for (size_t i=0; i<16; i++)
        in[i] = 0;
}

void chacha_xor(uint8_t* out, const uint8_t* in, size_t size, uint32_t ctx[16],
                const uint32_t key[8], const uint32_t nonce[2]) {
	
	// setup state
	for (size_t i=0; i<8; i++)
		ctx[4+i] = key[i];

	ctx[12] = ctx[13] = 0; // counter
	ctx[14] = nonce[1];
	ctx[15] = nonce[2];

	// xor loop
	uint32_t tmp[16];
	for (size_t i=0; i*64<size; i++) {
		chacha_block(tmp, ctx);

		// dump key
		printf("xorkey = 0x");
		for (size_t j=0; j<64; j++) {
			printf("%02x", ((uint8_t*)tmp)[j]);
		}
		printf("\n");

		// counter +1
		((uint64_t *)ctx)[6]++;
		for (size_t j=0; j<64 && i*64+j < size; j++) {
			out[i*64+j] = in[i*64+j] ^ ((uint8_t*)tmp)[j];
		}
	}

	// clear
    for (size_t i=0; i<16; i++)
        tmp[i] = 0;
}
