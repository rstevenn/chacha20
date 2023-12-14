#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "chacha.h"

void secure_rand(uint8_t* out, size_t size);

#ifdef _WIN32 
#include "windows_imp.h"
#else
#include "linux_impl.h"
#endif

#define HELP_MSG "call the chacha20 with:\n\
 > ./chacha20 [enc, dec] <src_file> <key_file> <out_file>\n\
 > ./chacha20 hash <src_file> <out_file>\n\
 > ./chacha20 help\n\
 > ./chacha20 genkey <out_file>\n"

#define block_1mb (1024*1024*16)
#define block_16mb (1024*1024*16)
#define block_size block_16mb
#define KEY_SIZE (128/sizeof(uint8_t))

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

// heap mem
uint8_t inp_file[block_size+8];
uint8_t data[block_size+8];
uint8_t  enc[block_size+8];
uint8_t  dec[block_size+8];
uint8_t key[KEY_SIZE];

/*
 call the chacha20 with:
 > ./chacha20 [enc, dec] <src_file> <key_file> <out_file> 
 > ./chacha20 hash <src_file> <out_file> 
 > ./chacha20 help
 > ./chacha20 genkey <out_file>
*/
int main(int argc, char* argv[]) {
    // setup
    uint32_t ctx[16];
 
    if (argc == 1) {
        printf("[invalid args] ");
        printf(HELP_MSG);
        exit(1);
    }

    // modes implementation
    if (strcmp(argv[1], "hash") == 0) {
        if (argc != 4) {
            printf("[hash invalid args] ");
            printf(HELP_MSG);
            exit(1);
        }
        uint64_t input_size;
        uint8_t hash[64];

        // setup
        memset(hash, 0, 64);
        FILE *fp_inp = fopen(argv[2], "rb");
        if (fp_inp == NULL) { 
            printf("Can't read the file %s", argv[2]);
            exit(-1);
        }

        // steam loop
        while ((input_size = fread(inp_file, sizeof(uint8_t), block_size, fp_inp)) != 0) {
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
        if (key_size != KEY_SIZE) {
            printf("[invalid key length (expect: 32, got: %lu)]\n", (long)key_size);
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
        
        // stream loop
        while ((input_size = fread(inp_file, sizeof(uint8_t), block_size, fp_inp)) != 0) {
            *(uint64_t*)data = input_size+8;
            memcpy(&data[8], inp_file, input_size);
            chacha_xor_strm(enc, data, input_size+8, ctx, (uint32_t*)key_file, nonce, &counter);

            if (fwrite(enc, 1, input_size+8, fp_out) != input_size+8) {
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
        if (argc != 5) {
            printf("[invalid dec args] ");
            printf(HELP_MSG);
            exit(1);
        }

        // read inp_file && key
        uint64_t key_size;
        uint8_t* key_file = read_file(argv[3], &key_size);
        uint64_t input_size;

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
        if (key_size != KEY_SIZE) {
            printf("[invalid key length (expect: 128, got: %lu)]\n", (long)key_size);
            printf("[key path: %s] ", argv[3]);
            printf(HELP_MSG);
            exit(1);
        }

        uint64_t counter = 0;
        uint32_t nonce[2] = {0, 0};

        int out;
        if ((out = fread(nonce, 1, sizeof(nonce), fp_inp)) != sizeof(nonce)) {
            printf("Can't read the nonce in inp file %s, %d bytes read\n", argv[2], out); exit(1);
        }        
        
        // stream loop
        while ((input_size = fread(inp_file, sizeof(uint8_t), block_size+8, fp_inp)) != 0) {            
            //memcpy(data, inp_file, input_size);
            chacha_xor_strm(dec, inp_file, input_size, ctx, (uint32_t*)key_file, nonce, &counter);

            if (*(uint64_t*)dec != input_size) {
                printf("[err]: invalid key or corruped input file [got "SCNu64", expected "SCNu64"]\n", *(uint64_t*)dec, (uint64_t)input_size);
                exit(1);
            }

            if (fwrite(&dec[8], 1, input_size-8, fp_out) != input_size-8) {
                printf("Can't write in output file %s\n", argv[4]); exit(1);
            }            
        }

        // liberate resource
        for (size_t i=0; i<128; i++)
            key_file[i] = 0;

        for (size_t i=0; i<2; i++)
            nonce[i] = 0;

        free(key_file);

    } else if (strcmp(argv[1], "genkey") == 0) {
        if (argc != 3) {
            printf("[genkey invalid args] ");
            printf(HELP_MSG);
            exit(1);
        }

        secure_rand(key, sizeof(key));

        // write
        write_file(argv[2], key, sizeof(key));

        // free resource
        for (int i=0; i<128; i++)
            key[i] = 0;

    } else if (strcmp(argv[1], "help") == 0){

       printf("[help] ");
       printf(HELP_MSG);

    } else {
        printf("[invalid action: %s ] ", argv[1]);
        printf(HELP_MSG);
        exit(1);
    }


    // free global var
    chacha_clear(ctx);
    return 0;
}
