#define _CRT_SECURE_NO_WARNINGS

#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define BLOCK_SIZE 16

/* ================= SBOX ================= */

static const uint8_t sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t inv_sbox[256] = {
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* ================= Rcon ================= */

static const uint8_t Rcon[11] =
{ 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36 };

/* ================= UTILS ================= */

static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}

static uint8_t multiply(uint8_t x, uint8_t y) {
    uint8_t r = 0;
    while (y) {
        if (y & 1) r ^= x;
        x = xtime(x);
        y >>= 1;
    }
    return r;
}

static void xor_block(uint8_t* a, const uint8_t* b) {
    for (int i = 0;i < 16;i++) 
        a[i] ^= b[i];
}

static void increment_counter(uint8_t* c) {
    for (int i = 15;i >= 0;i--) {
        c[i]++;
        if (c[i] != 0) break;
    }
}

/* ================= KEY EXPANSION ================= */

void AES_key_expansion(uint8_t* roundKeys, const uint8_t* key)
{
    memcpy(roundKeys, key, 16);
    for (int i = 4;i < 44;i++) {
        uint8_t t[4];
        memcpy(t, &roundKeys[(i - 1) * 4], 4);
        if (i % 4 == 0) {
            uint8_t temp = t[0];
            t[0] = sbox[t[1]] ^ Rcon[i / 4];
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[temp];
        }
        for (int j = 0;j < 4;j++)
            roundKeys[i * 4 + j] = roundKeys[(i - 4) * 4 + j] ^ t[j];
    }
}

/* ================= AES STEPS ================= */

static void AddRoundKey(uint8_t* state, const uint8_t* roundKey) {
    for (int i = 0;i < 16;i++) state[i] ^= roundKey[i];
}

static void SubBytes(uint8_t* state) {
    for (int i = 0;i < 16;i++) state[i] = sbox[state[i]];
}

static void InvSubBytes(uint8_t* state) {
    for (int i = 0;i < 16;i++) state[i] = inv_sbox[state[i]];
}

static void ShiftRows(uint8_t* s) {
    uint8_t tmp;
    tmp = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = tmp;
    tmp = s[2]; s[2] = s[10]; s[10] = tmp; tmp = s[6]; s[6] = s[14]; s[14] = tmp;
    tmp = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = tmp;
}

static void InvShiftRows(uint8_t* s) {
    uint8_t tmp;
    tmp = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = tmp;
    tmp = s[2]; s[2] = s[10]; s[10] = tmp; tmp = s[6]; s[6] = s[14]; s[14] = tmp;
    tmp = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = tmp;
}

static void MixColumns(uint8_t* s) {
    for (int i = 0;i < 4;i++) {
        int c = i * 4;
        uint8_t a[4], b[4];
        for (int j = 0;j < 4;j++) {
            a[j] = s[c + j];
            b[j] = xtime(a[j]);
        }
        s[c + 0] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
        s[c + 1] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
        s[c + 2] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
        s[c + 3] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
    }
}

static void InvMixColumns(uint8_t* s) {
    for (int i = 0;i < 4;i++) {
        int c = i * 4;
        uint8_t a0 = s[c + 0], a1 = s[c + 1], a2 = s[c + 2], a3 = s[c + 3];
        s[c + 0] = multiply(a0, 0x0e) ^ multiply(a1, 0x0b) ^ multiply(a2, 0x0d) ^ multiply(a3, 0x09);
        s[c + 1] = multiply(a0, 0x09) ^ multiply(a1, 0x0e) ^ multiply(a2, 0x0b) ^ multiply(a3, 0x0d);
        s[c + 2] = multiply(a0, 0x0d) ^ multiply(a1, 0x09) ^ multiply(a2, 0x0e) ^ multiply(a3, 0x0b);
        s[c + 3] = multiply(a0, 0x0b) ^ multiply(a1, 0x0d) ^ multiply(a2, 0x09) ^ multiply(a3, 0x0e);
    }
}

/* ================= ENCRYPT / DECRYPT BLOCK ================= */

void AES_encrypt_block(uint8_t* block, const uint8_t* roundKeys) {
    AddRoundKey(block, roundKeys);
    for (int round = 1;round < 10;round++) {
        SubBytes(block); ShiftRows(block); MixColumns(block);
        AddRoundKey(block, roundKeys + round * 16);
    }
    SubBytes(block); ShiftRows(block); AddRoundKey(block, roundKeys + 160);
}

void AES_decrypt_block(uint8_t* block, const uint8_t* roundKeys) {
    AddRoundKey(block, roundKeys + 160);
    for (int round = 9;round > 0;round--) {
        InvShiftRows(block); InvSubBytes(block);
        AddRoundKey(block, roundKeys + round * 16);
        InvMixColumns(block);
    }
    InvShiftRows(block); InvSubBytes(block); AddRoundKey(block, roundKeys);
}

/* ================= PADDING PKCS#7 ================= */

// Functii de padding PKCS#7
void AES_add_padding(uint8_t* data, size_t len, size_t block_size, size_t* out_len) {
    uint8_t pad = block_size - (len % block_size);
    for (size_t i = 0; i < pad; i++)
        data[len + i] = pad;
    *out_len = len + pad;
}

void AES_remove_padding(uint8_t* data, size_t* len) {
    uint8_t pad = data[*len - 1];
    if (pad > 0 && pad <= BLOCK_SIZE)
        *len -= pad;
}

/* ================= MODES ================= */

void AES_ECB_encrypt(uint8_t* data, size_t length) {
    uint8_t roundKeys[176]; AES_key_expansion(roundKeys, AES_KEY);
    for (size_t i = 0;i < length;i += 16) AES_encrypt_block(data + i, roundKeys);
}

void AES_ECB_decrypt(uint8_t* data, size_t length) {
    uint8_t roundKeys[176]; AES_key_expansion(roundKeys, AES_KEY);
    for (size_t i = 0;i < length;i += 16) AES_decrypt_block(data + i, roundKeys);
}

void AES_CBC_encrypt(uint8_t* data, size_t length) {
    uint8_t roundKeys[176];
    AES_key_expansion(roundKeys, AES_KEY);
    uint8_t iv[16]; 
    memcpy(iv, AES_IV, 16);
    for (size_t i = 0;i < length;i += 16) {
        xor_block(data + i, iv);
        AES_encrypt_block(data + i, roundKeys);
        memcpy(iv, data + i, 16);
    }
}

void AES_CBC_decrypt(uint8_t* data, size_t length) {
    uint8_t roundKeys[176]; AES_key_expansion(roundKeys, AES_KEY);
    uint8_t iv[16]; memcpy(iv, AES_IV, 16);
    uint8_t temp[16];
    for (size_t i = 0;i < length;i += 16) {
        memcpy(temp, data + i, 16);
        AES_decrypt_block(data + i, roundKeys);
        xor_block(data + i, iv);
        memcpy(iv, temp, 16);
    }
}

void AES_CTR_xcrypt(uint8_t* data, size_t length) {
    uint8_t roundKeys[176]; AES_key_expansion(roundKeys, AES_KEY);
    uint8_t counter[16]; memcpy(counter, AES_IV, 16);
    uint8_t stream[16];
    for (size_t i = 0;i < length;i += 16) {
        memcpy(stream, counter, 16);
        AES_encrypt_block(stream, roundKeys);
        for (int j = 0;j < 16 && i + j < length;j++) data[i + j] ^= stream[j];
        increment_counter(counter);
    }
}

/* ================= UTIL ================= */

void print_hex(uint8_t* data, size_t len) {
    for (size_t i = 0;i < len;i++) printf("%02x", data[i]);
    printf("\n");
}

// Citire fișier
uint8_t* read_file(const char* filename, size_t* out_len) {
    FILE* f = NULL;
    if (fopen_s(&f, filename, "rb") != 0 || f == NULL) {
        perror("fopen_s");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    *out_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t* buffer = (uint8_t*)malloc(*out_len + BLOCK_SIZE); // cast la uint8_t*
    if (!buffer) { fclose(f); return NULL; }

    fread(buffer, 1, *out_len, f);
    fclose(f);
    return buffer;
}

// Scriere fișier
void write_file(const char* filename, uint8_t* data, size_t len) {
    FILE* f = NULL;
    if (fopen_s(&f, filename, "wb") != 0 || f == NULL) {
        perror("fopen_s");
        return;
    }

    fwrite(data, 1, len, f);
    fclose(f);
}


int afisare_normala()
{
    uint8_t plaintext[64];
    size_t len = strlen("Ma duc sa iau paine zilnic!!");
    memcpy(plaintext, "Ma duc sa iau paine zilnic!!", len);

    size_t padded_len;
    AES_add_padding(plaintext, len, 16, &padded_len);

    printf("Original:\n%s\n\n", "Ma duc sa iau paine zilnic!! Apoi ma duc acasa si dupa seara ies in oras cu tovarasii");

    // ===== ALEGE MODUL =====
   
    // DECRYPT
    AES_CBC_encrypt(plaintext, padded_len);
    // AES_ECB_encrypt(plaintext,padded_len);
    // AES_CTR_xcrypt(plaintext,padded_len);

    printf("Encrypted (hex):\n");
    print_hex(plaintext, padded_len);
    
    // DECRYPT
    AES_CBC_decrypt(plaintext, padded_len);
    AES_remove_padding(plaintext, &padded_len);
    plaintext[padded_len] = '\0'; // foarte important!
    printf("Decrypted:\n%s\n", plaintext);

    printf("\nDecrypted:\n%s\n", plaintext);

    return 0;
}


// Test cu vectori de test pentru CBC 128
int test_CBC() {
    // ==== Cheie și IV NIST AES-128 ====
    uint8_t AES_KEY[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    uint8_t AES_IV[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    // ==== NIST Test Vector: 4 blocuri ====
    uint8_t plaintext[64] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
    };

    uint8_t roundKeys[176];
    AES_key_expansion(roundKeys, AES_KEY);

    uint8_t iv[16];
    memcpy(iv, AES_IV, 16);

    printf("==== CBC AES-128 NIST Test Vector ====\n");

    // Loop pe fiecare bloc
    for (int block = 0; block < 4; block++) {
        uint8_t input_block[16], output_block[16];
        memcpy(input_block, plaintext + block * 16, 16);

        // Input Block = Plaintext XOR IV (sau bloc precedent)
        xor_block(input_block, iv);

        // Criptare
        memcpy(output_block, input_block, 16);
        AES_encrypt_block(output_block, roundKeys);

        printf("Block #%d\n", block + 1);
        printf("Plaintext: ");
        print_hex(plaintext + block * 16, 16);
        printf("Input Block: ");
        print_hex(input_block, 16);
        printf("Output Block (Ciphertext): ");
        print_hex(output_block, 16);
        printf("\n");

        // Actualizează IV pentru următorul bloc
        memcpy(iv, output_block, 16);
    }

    return 0;
}

// Test cu vectori de test pentru ECB 128
int test_ECB() {
    // ==== Cheie NIST AES-128 ====
    uint8_t AES_KEY[16] = {
    0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
    };

    // Plaintext-uri (4 blocuri a câte 16 bytes)
    uint8_t plaintext[4][16] = {
        {0x6b,0xc1,0xbe,0xe2, 0x2e,0x40,0x9f,0x96, 0xe9,0x3d,0x7e,0x11, 0x73,0x93,0x17,0x2a},
        {0xae,0x2d,0x8a,0x57, 0x1e,0x03,0xac,0x9c, 0x9e,0xb7,0x6f,0xac, 0x45,0xaf,0x8e,0x51},
        {0x30,0xc8,0x1c,0x46, 0xa3,0x5c,0xe4,0x11, 0xe5,0xfb,0xc1,0x19, 0x1a,0x0a,0x52,0xef},
        {0xf6,0x9f,0x24,0x45, 0xdf,0x4f,0x9b,0x17, 0xad,0x2b,0x41,0x7b, 0xe6,0x6c,0x37,0x10}
    };

    uint8_t roundKeys[176];
    AES_key_expansion(roundKeys, AES_KEY);

    uint8_t iv[16];
    memcpy(iv, AES_IV, 16);

    printf("==== ECB AES-128 NIST Test Vector ====\n");

    // Loop pe fiecare bloc
    for (int block = 0; block < 4; block++) {
        uint8_t input_block[16];
        memcpy(input_block, plaintext[block], 16);

        // Criptare
        AES_encrypt_block(input_block, roundKeys);

        printf("Block #%d ECB Ciphertext: ", block + 1);
        print_hex(input_block, 16);

    }

    return 0;
}


int load_file(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: %s <enc|dec> <input file> <output file>\n", argv[0]);
        return 1;
    }

    const char* mode = argv[1];
    const char* input_file = argv[2];
    const char* output_file = argv[3];

    size_t len;
    uint8_t* data = read_file(input_file, &len);
    if (!data) return 1;

    size_t padded_len = len;

    if (strcmp(mode, "enc") == 0) {
        AES_add_padding(data, len, BLOCK_SIZE, &padded_len);
        AES_CBC_encrypt(data, padded_len);  // sau ECB / CTR
        write_file(output_file, data, padded_len);
        printf("File encrypted to %s\n", output_file);
    }
    else if (strcmp(mode, "dec") == 0) {
        AES_CBC_decrypt(data, len);
        padded_len = len;
        AES_remove_padding(data, &padded_len);
        write_file(output_file, data, padded_len);
        printf("File decrypted to %s\n", output_file);
    }
    else {
        printf("Unknown mode %s\n", mode);
    }

    free(data);
    return 0;
}

int main() {

    //afisare_normala();
    //test_CBC();
    test_ECB();
    //load_file();
    return 0;
}
