//#include <avr/io.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"

uint8_t OUT[128];
uint8_t Z[16];
uint8_t Y[16];
uint8_t ZERO[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

uint16_t ceil_(uint16_t x, uint16_t y)
{
    return x / y + (x % y != 0);
}

void aes(uint8_t *KEY, unsigned char *X, uint8_t n_X, unsigned char *buffer)
{
    aes_enc(KEY, X, buffer);
}

uint8_t get_bit(uint8_t x, uint8_t i)
{
    return ((x >> (i)) & ((uint8_t)1));
}
void set_bit(uint8_t *x, uint8_t i)
{
    *x |= (1 << i);
}
void clear_bit(uint8_t *x, uint8_t i)
{
    *x &= ~(1 << i);
}
void set_bit_with(uint8_t *x, uint8_t i, uint8_t what)
{
    if (what)
    {
        set_bit(x, i);
    }
    else
    {
        clear_bit(x, i);
    }
}
void inc(uint8_t *X, uint8_t n_X, uint8_t s) // n_X is the size of n_X
{
    uint8_t i, j;
    for (i = (n_X - 1); i >= (n_X - s); i--)
    {
        if (X[i] == 255)
        {
            if (i == n_X - s)
            {
                memset(X + i, 0, s);
            }
        }
        else
        {
            X[i] += 1;
            return;
        }
    }
}
void xor_block(uint8_t *blk, uint8_t *with, uint8_t n) // n is in bytes
{
    uint8_t i;
    for (i = 0; i < n; i++)
    {
        blk[i] ^= with[i];
    }
}
void block_right_shift(uint8_t *blk, uint8_t n_blk)
{
    uint8_t blk_tmp[n_blk];
    memcpy(blk_tmp, blk, n_blk);
    int8_t i;
    for (i = n_blk - 1; i >= 0; i--)
    {
        if (i != 0)
        {
            uint8_t carry = get_bit(blk[i - 1], 0);
            if (carry)
            {
                blk[i] = (blk[i] >> 1) | 0x80;
            }
            else
            {
                blk[i] = (blk[i] >> 1);
            }
        }
        else
        {
            blk[i] = (blk[i] >> 1);
        }
    }
}
void mult(uint8_t *x, uint8_t *y) // return Z
{
    uint8_t V[16], i, j;
    memset(Z, 0, 16);
    memcpy(V, y, 16);
    for (i = 0; i < 16; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (get_bit(x[i], 7 - j))
            {
                xor_block(Z, V, 16);
            } // else do nothing Z_i+1 = Z_i
            if (V[15] & 0x01)
            {
                block_right_shift(V, 16);
                V[0] ^= 0xE1;
            }
            else
            {
                block_right_shift(V, 16);
            }
        }
    }
}
void ghash(uint8_t *X, uint32_t m, uint8_t *H)
{
    // m is number of blocks
    uint8_t Y[16];
    memset(Y, 0, 16);
    uint8_t i;
    for (i = 0; i < m; i++)
    {
        xor_block(Y, X + (i * 16), 16);
        mult(Y, H); // value in Z
        memcpy(Y, Z, 16);
    }
}

void gctr(uint8_t *KEY, uint8_t *X, uint32_t n_X, uint8_t *Y, uint8_t *ICB) // for all blocks of size 16 bytes
{
    uint8_t CB[16], i;
    uint8_t cipher[16];
    memcpy(CB, ICB, 16);
    //hex(CB,1);
    if (n_X == 0)
    {
        memcpy(Y, X, 16);
        return;
    }
    for (i = 0; i < n_X; i++)
    {
        if (i > 0)
        {
            inc(CB, 16, 4); // 128 bit CB 32 bit s
            //hex(CB,1);
        }
        aes(KEY, CB, 1, cipher);
        xor_block(X + (i * 16), cipher, 16);
        memcpy(Y + (i * 16), X + (i * 16), 16);
    }
}

void authenticated_encryption(uint8_t *KEY, uint8_t *IV, uint8_t n_IV_b, uint8_t *P, uint8_t n_P, uint8_t *A, uint8_t n_A, uint8_t *C, uint8_t *T)
{
    uint8_t n_C = n_P;
    uint8_t *J;
    uint8_t n_J;
    uint8_t n_IV = n_IV_b / 8; // n_IV is in bytes

    // H = CIPH_k(0^128)
    uint8_t H[16];
    aes(KEY, ZERO, 1, H);
    // malloc C
    //C = (uint8_t *)malloc(n_P * 16);
    //uint8_t C[n_P * 16];

    // J = IV || 0^31||1
    if (n_IV == 12)
    {
        n_J = 16;
        J = (uint8_t *)malloc(n_J);
        memcpy(J, IV, 12);
        memcpy(J + 12, ZERO, 3);
        J[15] = 0x01;
        //hex(J,1);
    }
    else // J = GHASH(IV || 0^s+64 || len(IV)_64)
    {
        uint16_t s = 128 * ceil_(n_IV_b, 128) - n_IV_b;
        n_J = n_IV + 8 + ((s + 64) / 8);
        J = (uint8_t *)malloc(n_J);
        uint8_t ZERO_s[(s + 64) / 8];
        memset(ZERO_s, 0, (s + 64) / 8);
        memcpy(J, IV, n_IV);
        memset(J + n_IV, 0, (s + 64) / 8);

        uint8_t j;
        for (j = 0; j < 8; j++)
        {
            memset(J + n_IV + ((s + 64) / 8) + j, (uint64_t)n_IV_b >> 56 - (j * 8), 1);
        }
        ghash(J, n_J / 16, H);
        memcpy(J, Z, 16);
    }

    uint8_t J_tmp[n_J];
    memset(J_tmp, 0, n_J);
    memcpy(J_tmp, J, n_J);
    // C = GCTR_K(inc_32(J_0),P)
    inc(J, 16, 4);
    gctr(KEY, P, n_P, OUT, J);
    if (n_P == 0)
    {
        n_P += 1;
        memcpy(C, OUT, n_P * 16);
        n_P = 0;
    }
    else
    {
        memcpy(C, OUT, n_P * 16);
    }
    // u and v
    uint16_t u = 128 * ceil_(n_P * 16 * 8, 128) - n_P * 16 * 8;
    uint16_t v = 128 * ceil_(n_A * 16 * 8, 128) - n_A * 16 * 8;
    // S = GHASH_H(A || 0^v || C || 0^u || len(A)_64 || len(C)_64)
    uint8_t S[16];
    uint16_t n_S_input = n_A * 16 + (v / 8) + n_P * 16 + (u / 8) + 8 + 8;
    uint8_t *S_input;
    S_input = (uint8_t *)malloc(n_S_input);
    memcpy(S_input, A, n_A * 16);
    memset(S_input + 16 * n_A, 0, v / 8);

    memcpy(S_input + 16 * n_A + (v / 8), C, n_P * 16);

    memset(S_input + 16 * n_A + (v / 8) + 16 * n_P, 0, u / 8);

    uint8_t j;
    for (j = 0; j < 8; j++)
    {
        memset(S_input + 16 * n_A + (v / 8) + 16 * n_P + (u / 8) + j, (uint64_t)n_A * 16 * 8 >> 56 - (j * 8), 1);
    }
    for (j = 0; j < 8; j++)
    {
        memset(S_input + 16 * n_A + (v / 8) + 16 * n_P + (u / 8) + 8 + j, (uint64_t)n_P * 16 * 8 >> 56 - (j * 8), 1);
    }
    ghash(S_input, n_S_input / 16, H);
    memcpy(S, Z, 16); // is redundant?
    gctr(KEY, S, 1, OUT, J_tmp);
    memcpy(T, OUT, 16);
    free(S_input);
}

uint8_t authenticated_decrytion(uint8_t *KEY, uint8_t *IV, uint8_t n_IV_b, uint8_t *C, uint8_t n_C, uint8_t *A, uint8_t n_A, uint8_t *T, uint8_t *P)
{
    uint8_t j;
    uint8_t H[16];
    aes(KEY, ZERO, 1, H);

    uint8_t *T_original = (uint8_t *)malloc(16); // save T
    memcpy(T_original, T, 16);
    uint8_t *A_original = (uint8_t *)malloc(16); // save A
    memcpy(A_original, A, 16);

    uint8_t J[16];
    if (n_IV_b == 96)
    {
        memcpy(J, IV, 12);
        memset(J + 12, 0, 4);
        J[15] = 0x01;
        //hex(J,1);
    }
    else
    {
        uint16_t s = 128 * ceil_(n_IV_b, 128) - n_IV_b;
        uint8_t *input_tp_ghash = (uint8_t *)malloc(24 + ((s + 64) / 8));
        memcpy(input_tp_ghash, IV, n_IV_b / 8);
        memset(input_tp_ghash + (n_IV_b / 8), 0, ((s + 64) / 8));
        for (j = 0; j < 8; j++)
        {
            memset(input_tp_ghash + (n_IV_b / 8) + ((s + 64) / 8) + j, (uint64_t)n_IV_b >> 56 - (j * 8), 1);
        }
        ghash(input_tp_ghash, ((24 + ((s + 64) / 8)) / 16), H);
        memcpy(J, Z, 16);
        free(input_tp_ghash);
    }

    uint8_t *J_tmp = (uint8_t *)malloc(16); // using it in the other ghash
    memcpy(J_tmp, J, 16);
    inc(J_tmp, 16, 4);
    uint8_t *C_original = (uint8_t *)malloc(n_C * 16); // SAVE C
    memcpy(C_original, C, n_C * 16);
    gctr(KEY, C, n_C, P, J_tmp);

    //memcpy(P, OUT, n_C * 16);

    uint16_t u = 128 * ceil_(n_C * 16 * 8, 128) - n_C * 16 * 8;
    uint16_t v = 128 * ceil_(n_A * 16 * 8, 128) - n_A * 16 * 8;

    uint8_t *input_to_ghash = (uint8_t *)malloc(n_A * 16 + v + n_C * 16 + u + 16);
    memcpy(input_to_ghash, A_original, n_A * 16);
    memset(input_to_ghash + 16 * n_A, 0, v / 8);
    memcpy(input_to_ghash + 16 * n_A + (v / 8), C_original, n_C * 16);
    memset(input_to_ghash + 16 * n_A + (v / 8) + 16 * n_C, 0, u / 8);
    for (j = 0; j < 8; j++)
    {
        memset(input_to_ghash + 16 * n_A + (v / 8) + 16 * n_C + (u / 8) + j, (uint64_t)n_A * 16 * 8 >> 56 - (j * 8), 1);
    }
    for (j = 0; j < 8; j++)
    {
        memset(input_to_ghash + 16 * n_A + (v / 8) + 16 * n_C + (u / 8) + 8 + j, (uint64_t)n_C * 16 * 8 >> 56 - (j * 8), 1);
    }
    ghash(input_to_ghash, (n_A * 16 + v + n_C * 16 + u + 16) / 16, H);
    //hex(input_to_ghash, (n_A * 16 + v + n_C * 16 + u + 16) / 16);
    memcpy(J_tmp, Z, 16); // is redundant? J_tmp from previous ghash call
    //hex(J_tmp,1);
    gctr(KEY, J_tmp, 1, OUT, J);
    //hex(OUT,1);
    if (memcmp(OUT, T_original, 16) == 0)
    {
        free(J_tmp);
        free(A_original);
        free(C_original);
        free(input_to_ghash);
        free(T_original);
        return 1;
    }
    else
    {
        free(J_tmp);
        free(A_original);
        free(C_original);
        free(input_to_ghash);
        free(T_original);
        return 0;
    }
    //hex(OUT, 1);
}