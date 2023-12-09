#include <stdio.h>
#include "chacha.h"


// call the app with ./app_name <src_file> <key_file>
int main() {
    // setup
    uint32_t ctx[16];
    chacha_init(ctx);

    uint32_t key[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t nonce[2] = {0, 0};

    uint8_t in[] = "a realy realy realy realy long input or not, idk";
    uint8_t enc[sizeof(in)];
    uint8_t dec[sizeof(in)];

    // cipher
    chacha_xor(enc, in,  sizeof(in), ctx, key, nonce);
    chacha_xor(dec, enc, sizeof(in), ctx, key, nonce);

    printf("base = 0x");
	for (size_t j=0; j<sizeof(in); j++) {
		printf("%02x", in[j]);
    }
	printf("\n");

    printf("encr = 0x");
	for (size_t j=0; j<sizeof(enc); j++) {
		printf("%02x", enc[j]);
    }
	printf("\n");

    printf("decr = 0x");
	for (size_t j=0; j<sizeof(in); j++) {
		printf("%02x", dec[j]);
    }
	printf("\n");

    // clear and exit
    chacha_clear(ctx);
    printf("end\n");
    return 0;
}