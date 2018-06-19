#include <stdint.h>

void aes_dec(uint8_t *KEY, char *ciphertext, char *buffer);
void aes_enc(uint8_t *KEY, char *plaintext, char *buffer);
