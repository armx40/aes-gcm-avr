#include <avr/io.h>

uint8_t authenticated_decrytion(uint8_t *KEY, uint8_t *IV, uint8_t n_IV_b, uint8_t *C, uint8_t n_C, uint8_t *A, uint8_t n_A, uint8_t *T, uint8_t *P);

void authenticated_encryption(uint8_t *KEY, uint8_t *IV, uint8_t n_IV_b, uint8_t *P, uint8_t n_P, uint8_t *A, uint8_t n_A, uint8_t *C, uint8_t *T);
