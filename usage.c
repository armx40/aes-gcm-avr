#include <stdio.h>
#include "aes-gcm.h"

char buffer[12];

int main()
{
    uint8_t P[] = "12345678abcdefgh";
    uint8_t k[] = {0xfe, 0x9c, 0xb0, 0xd7, 0x75, 0x3d, 0x80, 0x68, 0x66, 0x21, 0xfc, 0xf2, 0x87, 0x05, 0xa3, 0x9a};
    uint8_t iv[] = {0xbd, 0x71, 0x58, 0x6f, 0x25, 0x09, 0x81, 0x42, 0x83, 0xca, 0x1e, 0xc8};
    uint8_t A[] = {0x86, 0x76, 0xd9, 0xc9, 0x95, 0x23, 0x40, 0xc3, 0x1c, 0x9e, 0xb9, 0xe0, 0xd7, 0x5c, 0x68, 0xd4};
    char T[16];
    char C[16];
    authenticated_encryption(k, iv, 96, T, 0, A, 1, T, T); // KEY, IV, IV SIZE IN BITS, POINTER TO PLAINTEXT, SIZE OF PLAINTEXT DIVIDE BY 16, ADDITIONAL AUTHENTICATED DATA, SIZE OF ADDITIONAL AUTHENTICATED DATA DIVIDED BY 16, POINTER TO CIPHER BUFFER, POINTER TO TAG BUFFER
    authenticated_decrytion(k, iv, 96, T, 0, A, 1, T, T);  // KEY, IV, IV SIZE IN BITS, POINTER TO CIPHERTEXT, SIZE OF CIPHERTEXT DIVIDE BY 16, ADDITIONAL AUTHENTICATED DATA, SIZE OF ADDITIONAL AUTHENTICATED DATA DIVIDED BY 16, POINTER TO TAG, POINTER TO PLAINTEXT BUFFER | RETURNS 1 ON SUCCESSFULL AUTHENTICATION ELSE 0
}