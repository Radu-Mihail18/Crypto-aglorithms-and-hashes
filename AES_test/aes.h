#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16
#define AES_ROUNDS 10

// Cheie fixa (128 biti)
static const uint8_t AES_KEY[16] = {
    0x2b,0x7e,0x15,0x16,
    0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,
    0x09,0xcf,0x4f,0x3c
};

// IV pentru CBC si CTR (16 bytes)
static const uint8_t AES_IV[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f
};

// ===== AES pe bloc =====
void AES_encrypt_block(uint8_t state[4][4]);
void AES_decrypt_block(uint8_t state[4][4]);

// ===== Moduri de operare =====
void AES_ECB_encrypt(uint8_t* data, size_t length);
void AES_ECB_decrypt(uint8_t* data, size_t length);

void AES_CBC_encrypt(uint8_t* data, size_t length);
void AES_CBC_decrypt(uint8_t* data, size_t length);

void AES_CTR_xcrypt(uint8_t* data, size_t length);

#endif