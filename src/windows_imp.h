#include <stdio.h>
#include <stdint.h>
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