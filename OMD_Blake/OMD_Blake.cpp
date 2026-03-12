#define _CRT_SECURE_NO_WARNINGS 
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ================= CONFIG ================= */
#define OMD_n 32
#define OMD_m 32

/* ================= BLAKE-256 STRUCT ================= */
typedef struct {
    uint32_t h[8];
    uint32_t s[4];
    uint32_t t[2];
    int buflen;
    int nullt;
    uint8_t buf[64];
} state256;

/* ================= BLAKE-256 CONSTANTS ================= */
static const uint32_t constant[16] = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917
};

/* ================= MACRO HELPER ================= */
#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define U8TO32_BIG(p) ((uint32_t)(p)[0]<<24 | (uint32_t)(p)[1]<<16 | (uint32_t)(p)[2]<<8 | (uint32_t)(p)[3])
#define U32TO8_BIG(p,v) do { \
    (p)[0]=(uint8_t)((v)>>24); (p)[1]=(uint8_t)((v)>>16); \
    (p)[2]=(uint8_t)((v)>>8);  (p)[3]=(uint8_t)(v); } while(0)

/* ================= G FUNCTION ================= */
static void G(uint32_t v[16], const uint32_t m[16], int r, int a, int b, int c, int d, int s)
{
    int i = r % 16;
    v[a] = v[a] + v[b] + (m[(2 * i + s) % 16] ^ constant[(2 * i + s + 1) % 16]);
    v[d] = ROTR32(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + (m[(2 * i + s + 1) % 16] ^ constant[(2 * i + s) % 16]);
    v[d] = ROTR32(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d];
    v[b] = ROTR32(v[b] ^ v[c], 7);
}

/* ================= INITIALIZE ================= */
void initialize(state256* S)
{
    S->h[0] = 0x6a09e667; S->h[1] = 0xbb67ae85;
    S->h[2] = 0x3c6ef372; S->h[3] = 0xa54ff53a;
    S->h[4] = 0x510e527f; S->h[5] = 0x9b05688c;
    S->h[6] = 0x1f83d9ab; S->h[7] = 0x5be0cd19;
    S->t[0] = S->t[1] = S->buflen = S->nullt = 0;
    S->s[0] = S->s[1] = S->s[2] = S->s[3] = 0;
    memset(S->buf, 0, 64);
}

/* ================= ROUND FUNCTION ================= */
void round_function(state256* S, const uint8_t* block)
{
    uint32_t v[16], m[16];
    for (int i = 0; i < 16; i++)
        m[i] = U8TO32_BIG(block + 4 * i);

    for (int i = 0; i < 8; i++)
        v[i] = S->h[i];

    v[8] = S->s[0] ^ constant[0]; v[9] = S->s[1] ^ constant[1];
    v[10] = S->s[2] ^ constant[2]; v[11] = S->s[3] ^ constant[3];
    v[12] = constant[4]; v[13] = constant[5];
    v[14] = constant[6]; v[15] = constant[7];

    for (int i = 0; i < 14; i++)
    {
        G(v, m, i, 0, 4, 8, 12, 0);
        G(v, m, i, 1, 5, 9, 13, 2);
        G(v, m, i, 2, 6, 10, 14, 4);
        G(v, m, i, 3, 7, 11, 15, 6);

        G(v, m, i, 0, 5, 10, 15, 8);
        G(v, m, i, 1, 6, 11, 12, 10);
        G(v, m, i, 2, 7, 8, 13, 12);
        G(v, m, i, 3, 4, 9, 14, 14);
    }

    for (int i = 0; i < 16; i++)
        S->h[i % 8] ^= v[i];

    for (int i = 0; i < 8; i++)
        S->h[i] ^= S->s[i % 4];
}

/* ================= BLAKE256 COMP ================= */
void BLAKE256_COMP(uint8_t* out, const uint8_t* H_in, const uint8_t* block)
{
    state256 S;
    initialize(&S);
    for (int i = 0; i < 8; i++)
        S.h[i] = U8TO32_BIG(H_in + 4 * i);
    S.t[0] = S.t[1] = 0; S.nullt = 1;
    memset(S.s, 0, sizeof(S.s));
    S.buflen = 0;
    round_function(&S, block);
    for (int i = 0; i < 8; i++)
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
    if (carry) block[OMD_n - 1] ^= 0x87;
}

/* ================= KEY FUNCTION F_K ================= */
static void key_func(uint8_t* out, const uint8_t* K, const uint8_t* H, const uint8_t* M)
{
    uint8_t block[64] = { 0 };
    memcpy(block, K, OMD_n);
    memcpy(block + OMD_n, M, OMD_m);
    BLAKE256_COMP(out, H, block);
}

/* ================= OMD ENCRYPT ================= */
int omd_encrypt(uint8_t* ciphertext, uint8_t* tag,
    const uint8_t* key, const uint8_t* nonce,
    const uint8_t* plaintext, size_t len)
{
    if (len != OMD_m) return -1;

    uint8_t H[OMD_n] = { 0 }, L[OMD_n] = { 0 }, offset[OMD_n] = { 0 }, tmp[OMD_n] = { 0 };

    memcpy(H, nonce, 12);

    uint8_t zero[OMD_m] = { 0 };
    key_func(L, key, H, zero);
    memcpy(offset, L, OMD_n);

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
    if (len != OMD_m) return -1;

    uint8_t H[OMD_n] = { 0 }, L[OMD_n] = { 0 }, offset[OMD_n] = { 0 }, tmp[OMD_n] = { 0 };
    memcpy(H, nonce, 12);

    uint8_t zero[OMD_m] = { 0 };
    key_func(L, key, H, zero);
    memcpy(offset, L, OMD_n);

    double_block(offset);
    xor_block(tmp, ciphertext, offset, OMD_m);
    key_func(H, key, H, tmp);
    xor_block(plaintext, H, offset, OMD_m);

    if (memcmp(tag, H, OMD_n) != 0) return -1;
    return 0;
}

/* ===================== VECTORI DE TEST ===================== */
typedef struct {
    uint8_t key[OMD_n];
    uint8_t nonce[12];
    uint8_t plaintext[OMD_m];
} test_vector_t;

test_vector_t tests[] = {
    {
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f}, // Key
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b},
        {0}
    },
    {
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f},
        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0c},
        {0}
    },
};

/* ======================== MAIN ======================== */
int main()
{
    /* Setăm plaintext-uri de exact 32 bytes */
    uint8_t pt0[OMD_m] = {
    'H','e','l','l','o',' ','O','M','D',' ','w','i','t','h',' ',
    'B','L','A','K','E','!','!','!','!','H','e','l','l','o',' ','O','M'
    };

    uint8_t pt1[OMD_m] = {
        'A','n','o','t','h','e','r',' ','t','e','s','t',' ','v','e','c',
        't','o','r',' ','f','o','r',' ','O','M','D','-','B','L','A','K'
    };

    memcpy(tests[0].plaintext, pt0, OMD_m);
    memcpy(tests[1].plaintext, pt1, OMD_m);

    int num_tests = sizeof(tests) / sizeof(tests[0]);

    for (int i = 0; i < num_tests; i++) {
        uint8_t ciphertext[OMD_m];
        uint8_t decrypted[OMD_m];
        uint8_t tag[OMD_n];

        printf("\n--- Test vector %d ---\n", i + 1);

        /* Plaintext */
        printf("Plaintext hex   : ");
        for (int j = 0; j < OMD_m; j++) printf("%02x", tests[i].plaintext[j]);
        printf("\nPlaintext ASCII : ");
        for (int j = 0; j < OMD_m; j++)
            printf("%c", (tests[i].plaintext[j] >= 32 && tests[i].plaintext[j] <= 126) ? tests[i].plaintext[j] : '.');
        printf("\n");

        /* Encrypt */
        omd_encrypt(ciphertext, tag, tests[i].key, tests[i].nonce, tests[i].plaintext, OMD_m);

        printf("Ciphertext      : ");
        for (int j = 0; j < OMD_m; j++) printf("%02x", ciphertext[j]);
        printf("\nTag             : ");
        for (int j = 0; j < OMD_n; j++) printf("%02x", tag[j]);
        printf("\n");

        /* Decrypt */
        int ret = omd_decrypt(decrypted, tag, tests[i].key, tests[i].nonce, ciphertext, OMD_m);

        printf("Decrypted hex   : ");
        for (int j = 0; j < OMD_m; j++) printf("%02x", decrypted[j]);
        printf("\nDecrypted ASCII : ");
        for (int j = 0; j < OMD_m; j++)
            printf("%c", (decrypted[j] >= 32 && decrypted[j] <= 126) ? decrypted[j] : '.');
        printf("\n");

        if (ret == 0)
            printf("Tag valid\n");
        else
            printf("Tag invalid!\n");
    }

    return 0;
}