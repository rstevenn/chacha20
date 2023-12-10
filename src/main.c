#include <stdio.h>
#include "chacha.h"

void secure_rand(uint8_t* out, size_t size);

#ifdef _WIN32 
#include <windows.h>
#include <wincrypt.h>
# pragma comment(lib, "advapi32.lib")

void secure_rand(uint8_t* out, size_t size)
{
    HCRYPTPROV hCryptProv;
    LPCSTR UserName = "chacha20";

    // get ctx
    if(!CryptAcquireContext(
        &hCryptProv,               // handle to the CSP
        UserName,                  // container name 
        NULL,                      // use the default provider
        PROV_RSA_FULL,             // provider type
        0))                        // flag values
    {
        printf("[ERR]: Can't access ctx provider");
        exit(1);
    }

    // generate
    if (!CryptGenRandom(hCryptProv, size, out)) {
        printf("[ERR]: Can't generate random nb");
        exit(1);
    }

    // release ctx
    if (!CryptReleaseContext(hCryptProv, 0))
    {
        printf("[WRN]: The handle could not be released.\n");
    }
}
#else

#endif

// call the app with ./app_name <src_file> <key_file>
int main() {
    // setup
    uint32_t ctx[16];
    chacha_init(ctx);

    uint32_t key[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t nonce[2] = {0, 0};

    secure_rand((uint8_t*)key,   4*sizeof(key));
    secure_rand((uint8_t*)nonce, 4*sizeof(nonce));

    uint8_t in[] = "a realy realy realy realy long input or not, idk. Maybe shoul'd I say something else like: let's all love lain";
    uint8_t enc[sizeof(in)];
    uint8_t dec[sizeof(in)];
    uint8_t hash[64]; 

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

    // hash
    chacha_hash((uint32_t*)hash, ctx, enc, sizeof(in));
    
    printf("hash enc = 0x");
	for (size_t j=0; j<sizeof(hash); j++) {
		printf("%02x", hash[j]);
    }
	printf("\n");


    chacha_hash((uint32_t*)hash, ctx, in, sizeof(in));
    
    printf("hash dec = 0x");
	for (size_t j=0; j<sizeof(hash); j++) {
		printf("%02x", hash[j]);
    }
	printf("\n");

    // clear and exit
    for (size_t i=0; i<sizeof(key); i++)
        key[i] = 0;

    for (size_t i=0; i<sizeof(nonce); i++)
        nonce[i] = 0;


    chacha_clear(ctx);
    printf("end\n");
    return 0;
}