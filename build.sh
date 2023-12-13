#!/bin/sh
set -ex

gcc -Ofast -flto src/chacha.c src/main.c -o bin/chacha20
