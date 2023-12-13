# chacha20
A c implementation of chacha20 cipher and a hash based on it
!! Probably not secure and full of vulenrability

# build
## requirement
* gcc

## linux
> ./build.sh

## windows
to implement

# run
## doc
call chacha20 with:
 > ./chacha20 (enc, dec) <src_file> <key_file> <out_file>  # encrypt/decrypt a file
 > ./chacha20 hash <src_file> <out_file> # hash a file
 > ./chacha20 help                          
 > ./chacha20 genkey <out_file> # generate a 128bits key file

## linux
> ./bin/chacha20

## windows
> ./bin/chacha20.exe

# src
- https://en.wikipedia.org/wiki/Salsa20


