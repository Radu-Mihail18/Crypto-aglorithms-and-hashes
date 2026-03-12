#define _CRT_SECURE_NO_WARNINGS
#include "blake_header.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* dimensiuni pentru BLAKE-256 / OMD */
#define OMD_n 32
#define OMD_m 32

/* ================= BLAKE256 COMPRESSION ================= */
void BLAKE256_COMP(uint8_t* out, const uint8_t* H_in, const uint8_t* block)
{
    state256 S;
    int i;

    initialize(&S);

    /* chaining value extern */
    for (i = 0; i < 8; i++)
        S.h[i] = U8TO32_BIG(H_in + 4 * i);

    /* dezactivăm contorul */
    S.t[0] = S.t[1] = 0;
    S.nullt = 1;

    /* salt nu se folosește */
    S.s[0] = S.s[1] = S.s[2] = S.s[3] = 0;

    S.buflen = 0;

    /* compresie pe blocul de 64 bytes */
    round_function(&S, block);

    /* exportăm noul chaining value */
    for (i = 0; i < 8; i++)
        U32TO8_BIG(out + 4 * i, S.h[i]);
}

/* ================= UTILITARE ================= */
static void xor_block(uint8_t* out, const uint8_t* a, const uint8_t* b, size_t len)
{
    for (size_t i = 0; i < len; i++)
        out[i] = a[i] ^ b[i];
}

static void double_block(uint8_t* block)
{
    uint8_t carry = 0;
    for (int i = OMD_n - 1; i >= 0; i--)
    {
        uint8_t newcarry = block[i] >> 7;
        block[i] = (block[i] << 1) | carry;
        carry = newcarry;
    }
    if (carry)
        block[OMD_n - 1] ^= 0x87;
}

/* ================= KEY FUNCTION F_K ================= */
static void key_func(uint8_t* out, const uint8_t* K, const uint8_t* H, const uint8_t* M)
{
    uint8_t block[64];
    memcpy(block, K, OMD_n);
    memcpy(block + OMD_n, M, OMD_m);
    BLAKE256_COMP(out, H, block);
}

/* ================= OMD ENCRYPT ================= */
int omd_encrypt(uint8_t* ciphertext, uint8_t* tag,
    const uint8_t* key, const uint8_t* nonce,
    const uint8_t* plaintext, size_t len)
{
    if (len != OMD_m)
        return -1;  // pentru test simplificat: doar 32 bytes

    uint8_t H[OMD_n], L[OMD_n], offset[OMD_n], tmp[OMD_n];

    /* H0 = nonce || padding 0 */
    memset(H, 0, OMD_n);
    memcpy(H, nonce, 12);

    /* L = F_K(H, 0^n) */
    uint8_t zero[OMD_m] = { 0 };
    key_func(L, key, H, zero);

    memcpy(offset, L, OMD_n);

    /* un singur block pentru test */
    double_block(offset);
    xor_block(tmp, plaintext, offset, OMD_m);
    key_func(H, key, H, tmp);
    xor_block(ciphertext, H, offset, OMD_m);

    memcpy(tag, H, OMD_n);

    return 0;
}

/* ================= OMD DECRYPT ================= */
int omd_decrypt(uint8_t* plaintext, const uint8_t* tag,
    const uint8_t* key, const uint8_t* nonce,
    const uint8_t* ciphertext, size_t len)
{
    if (len != OMD_m)
        return -1;  // pentru test simplificat: doar 32 bytes

    uint8_t H[OMD_n], L[OMD_n], offset[OMD_n], tmp[OMD_n];

    memset(H, 0, OMD_n);
    memcpy(H, nonce, 12);

    uint8_t zero[OMD_m] = { 0 };
    key_func(L, key, H, zero);

    memcpy(offset, L, OMD_n);

    double_block(offset);
    xor_block(tmp, ciphertext, offset, OMD_m);
    key_func(H, key, H, tmp);
    xor_block(plaintext, H, offset, OMD_m);

    if (memcmp(tag, H, OMD_n) != 0)
        return -1;

    return 0;
}

/* ================= TEST ================= */
int main()
{
    uint8_t key[OMD_n] = { 0 };
    uint8_t nonce[12] = { 0 };
    uint8_t plaintext[OMD_m] = { 0 };
    memcpy(plaintext, "Hello OMD with BLAKE!!!!", 25);

    uint8_t ciphertext[OMD_m];
    uint8_t decrypted[OMD_m];
    uint8_t tag[OMD_n];

    omd_encrypt(ciphertext, tag, key, nonce, plaintext, OMD_m);

    printf("Ciphertext: ");
    for (int i = 0; i < OMD_m; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    if (omd_decrypt(decrypted, tag, key, nonce, ciphertext, OMD_m) == 0)
    {
        printf("Decrypted: %s\n", decrypted);
    }
    else
    {
        printf("Tag invalid!\n");
    }

    return 0;
}