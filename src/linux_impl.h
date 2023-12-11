#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void secure_rand(uint8_t* out, size_t size) {
    FILE* fp = fopen("/dev/urandom", "rb");
    if (fp == NULL) {
        printf("Can't access random générator\n");
        exit(1);
    }

    if (fread(out, sizeof(*out), size, fp) != size) {
        printf("Can't generate random bytes\n");
        exit(1);
    }
    fclose(fp);
}