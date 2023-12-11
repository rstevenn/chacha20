#include <stdio.h>
#include <string.h>
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


#define HELP_MSG "call the app with:\n\
 > ./app_name [enc, dec] <src_file> <key_file> <out_file>\n\
 > ./app_name hash <src_file> <out_file> "

#define block_16mb (1024*1024*16)

uint8_t *read_file(char *path, uint64_t* size) {
    // open file
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) { 
        printf("Can't read the file %s", path);
        exit(-1);
    }

    // get file size    
    fseek(fp, 0, SEEK_END);
    *size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    printf("%llu\n", *size);
 

    // read data
    uint8_t *buffer = (uint8_t *)malloc(sizeof(uint8_t) * (*size));
    if (buffer == NULL) {
        printf("Unable to allocate a buffer of %llu chars", *size);
        exit(1);
    }

    size_t got = fread(buffer, sizeof(uint8_t), *size, fp);
    if (*size != got) { 
        printf("unable to read the file %s (expected %lu != got %lu)",
                path, (unsigned long)*size, (unsigned long)got);
        exit(-1);
    }

    // close file
    fclose(fp);
    return buffer;
}

void write_file(char *path, const uint8_t* data, long size) {
    // open file
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) { 
        printf("Can't write the file %s", path);
        exit(-1);
    }

    size_t got = fwrite(data, sizeof(data[0]), size, fp);
    if (got != size) {
        printf("unable to write in the file %s (expected %lu != got %lu)",
                path, (unsigned long)size, (unsigned long)got);
        exit(-1);
    }

    fclose(fp);
}

/*
 call the app with:
 > ./app_name [enc, dec] <src_file> <key_file> <out_file> 
 > ./app_name hash <src_file> <out_file> 
*/
int main(int argc, char* argv[]) {
    // setup
    uint32_t ctx[16];

    // parse args
    if (argc < 4) {
        printf("[invalid args] ");
        printf(HELP_MSG);
        exit(1);
    }
    
    // modes implementation
    if (strcmp(argv[1], "hash") == 0) {
        uint64_t input_size;
        uint8_t inp_file[block_16mb];
        uint8_t hash[64];

        // setup
        memset(hash, 0, 64);
        FILE *fp_inp = fopen(argv[2], "rb");
        if (fp_inp == NULL) { 
            printf("Can't read the file %s", argv[2]);
            exit(-1);
        }

        // steam loop
        while ((input_size = fread(inp_file, sizeof(uint8_t), block_16mb, fp_inp)) != 0) {
            chacha_hash((uint32_t*)hash, ctx, inp_file, input_size);
        }
        write_file(argv[3], hash, sizeof(hash));

        // free resource
        fclose(fp_inp);

    } else if (strcmp(argv[1], "enc") == 0) {
        // check args
        if (argc != 5) {
            printf("[invalid enc args] ");
            printf(HELP_MSG);
            exit(1);
        }

        // read inp_file && key
        uint64_t key_size;
        uint8_t* key_file = read_file(argv[3], &key_size);
        uint64_t input_size;
        uint8_t inp_file[block_16mb];

        FILE *fp_inp = fopen(argv[2], "rb");
        if (fp_inp == NULL) { 
            printf("Can't read the file %s", argv[2]);
            exit(-1);
        }

        FILE *fp_out = fopen(argv[4], "wb");
        if (fp_out == NULL) { 
            printf("Can't read the file %s", argv[4]);
            exit(-1);
        }

        // setup data
        if (key_size != 128) {
            printf("[invalid key length (expect: 128, got: %lu)]\n", (long)key_size);
            printf("[key path: %s] ", argv[3]);
            printf(HELP_MSG);
            exit(1);
        }

        uint64_t counter = 0;
        uint32_t nonce[2] = {0, 0};
        secure_rand((uint8_t*)nonce, sizeof(nonce));

        if (fwrite(nonce, 1, sizeof(nonce), fp_out) != sizeof(nonce)) {
            printf("Can't write in output file %s\n", argv[4]); exit(1);
        }
;        
        uint8_t data[block_16mb];
        uint8_t  enc[block_16mb];


        // stream loop
        size_t i=0;
        while ((input_size = fread(inp_file, sizeof(uint8_t), block_16mb-1, fp_inp)) != 0) {
            i++;
            printf("block %llu\n", i);
            
            *(uint64_t*)data = input_size+1;
            memcpy(&data[8], inp_file, input_size);
            chacha_xor_strm(enc, data, input_size+1, ctx, (uint32_t*)key_file, nonce, &counter);

            if (fwrite(enc, 1, input_size+1, fp_out) != input_size+1) {
                printf("Can't write in output file %s\n", argv[4]); exit(1);
            }            
        }

        // liberate resource
        for (size_t i=0; i<128; i++)
            key_file[i] = 0;

        for (size_t i=0; i<2; i++)
            nonce[i] = 0;

        fclose(fp_inp);
        fclose(fp_out);
        free(key_file);

    } else if (strcmp(argv[1], "dec") == 0) {
        // check args
        if (argc < 5) {
            printf("[invalid dec args] ");
            printf(HELP_MSG);
            exit(1);
        }

        // read inp_file && key
        uint64_t input_size;
        uint64_t key_size;
        uint8_t* inp_file = read_file(argv[2], &input_size);
        uint8_t* key_file = read_file(argv[3], &key_size);

        if (key_size != 128) {
            printf("[invalid key length (expect: 128, got: %llu)]\n", key_size);
            printf("[key path: %s] ", argv[3]);
            printf(HELP_MSG);
            exit(1);
        }

        // setup decode data
        uint32_t nonce[2] = {0, 0};
        ((uint64_t*)nonce)[0] = ((uint64_t*)inp_file)[0];

        uint64_t data_size = input_size-sizeof(uint64_t);        
        uint8_t* data = (uint8_t*)malloc(sizeof(uint8_t)*data_size);
        uint8_t* dec  = (uint8_t*)malloc(sizeof(uint8_t)*input_size);

        // decode and write
        chacha_xor(dec, &inp_file[8], data_size, ctx, (uint32_t*)key_file, nonce);
        if (((uint64_t*)dec)[0] != (uint64_t)input_size-sizeof(uint64_t)) {
            printf("[err]: invalid key (got: %llu, expected: %llu)\n", 
                    ((uint64_t*)dec)[0], (uint64_t)input_size-sizeof(uint64_t));
            exit(1);
        }
        memcpy(data, &(dec[8]), data_size);
        write_file(argv[4], data, data_size);

        // liberate resource
        for (size_t i=0; i<128; i++)
            key_file[i] = 0;

        for (size_t i=0; i<2; i++)
            nonce[i] = 0;

        free(key_file);
        free(inp_file);
        free(data);
        free(dec);

    } else {
        printf("[invalid action: %s ] ", argv[1]);
        printf(HELP_MSG);
        exit(1);
    }


    // free global var
    chacha_clear(ctx);
    printf("end\n");
    return 0;
}