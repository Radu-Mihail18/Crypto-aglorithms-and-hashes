/*



#define _CRT_SECURE_NO_WARNINGS
#include "blake_header.h"

// initialization of states
void initialize(state256* S)
{
    S->h[0] = 0x6a09e667;
    S->h[1] = 0xbb67ae85;
    S->h[2] = 0x3c6ef372;
    S->h[3] = 0xa54ff53a;
    S->h[4] = 0x510e527f;
    S->h[5] = 0x9b05688c;
    S->h[6] = 0x1f83d9ab;
    S->h[7] = 0x5be0cd19;
    S->t[0] = S->t[1] = S->buflen = S->nullt = 0;  // t[0] -> t_low, t[1] -> t_high
    // nullt -> flag special pt ultimul bloc de flux
    S->s[0] = S->s[1] = S->s[2] = S->s[3] = 0;    // aici se produce saltul de la s[0] la s[1], apoi la s[2], apoi la s[3]
    // aici este 0 deoarece nu se foloseste
}

// round function
void round_function(state256* S, const uint8_t* block)
{
    // states and message block - 32-bit each
    uint32_t v[16], m[16], i;

    // convert take 8-bit blocks into 32-bit and big-endian format
    for (i = 0; i < 16; ++i)
        m[i] = U8TO32_BIG(block + i * 4); // aici, la fiecare byte il transforma in big endian

    // initial states
    for (i = 0; i < 8; ++i)
        v[i] = S->h[i]; // S[] fiind 0 => raman doar valorile din h[i], care sunt declarate initial, la fel ca in SHA256

    // rest states
    v[8] = S->s[0] ^ constant[0];
    v[9] = S->s[1] ^ constant[1];
    v[10] = S->s[2] ^ constant[2];
    v[11] = S->s[3] ^ constant[3];
    v[12] = constant[4];
    v[13] = constant[5];
    v[14] = constant[6];
    v[15] = constant[7];
    // S[] fiind 0 => raman doar constantele

    // XOR with t is not required when the block has padding-bits
    if (!S->nullt)
    {
        v[12] ^= S->t[0];
        v[13] ^= S->t[0];
        v[14] ^= S->t[1];
        v[15] ^= S->t[1];
    }
    // aici se introduce pozoitia blocul de flux
    // nullt este folosit ca padding final, atunci cand blocul nu trebuie sa contina contorul
    // daca nullt = 1, atunci contorul nu se mai injecteaza in starea v, si nu vrem asta, doar in cazul in care vrem padding

    // run the core function 14 times for blake-256 hash
    for (i = 0; i < 14; ++i)
    {
        // column step
        G(v, m, i, 0, 4, 8, 12, 0);
        G(v, m, i, 1, 5, 9, 13, 2);
        G(v, m, i, 2, 6, 10, 14, 4);
        G(v, m, i, 3, 7, 11, 15, 6);
        // diagonal step
        G(v, m, i, 0, 5, 10, 15, 8);
        G(v, m, i, 1, 6, 11, 12, 10);
        G(v, m, i, 2, 7, 8, 13, 12);
        G(v, m, i, 3, 4, 9, 14, 14);
    }

    //Finalizarea blocului

    // generating the hash with all updated states
    for (i = 0; i < 16; ++i)
        S->h[i % 8] ^= v[i];

    for (i = 0; i < 8; ++i)
        S->h[i] ^= S->s[i % 4];
}

// update the length of the block left and to fill
// functia pad_and_round umple bufferul si apeleaza functia cand sunt 64 de bytes
void pad_and_round(state256* S, const uint8_t* in, uint64_t inlen)
{
    // space already filled
    int left = S->buflen; // constanta pt a vedea daca bufferul este plin

    // space left in buffer
    int fill = 64 - left; // constanta pt a vedea daca mai este spatiu in buffer

    // data left is not null and data to be left is greater than available space
    if (left && (inlen >= fill)) // conditie care veridica daca spatiul este plin sau nu, si daca datele care urmeaza sa intre sunt mai multe decat permite spatiul
    {
        memcpy((void*)(S->buf + left), (void*)in, fill);
        S->t[0] += 512; // daca bufferul e plin, adauga cei 512 biti procesati

        if (S->t[0] == 0)
            S->t[1]++; // daca avem overflow, atunci t[0] (t_low) devine 0, iar t[1] (t_high) creste cu 1

        round_function(S, S->buf);
        in += fill;
        inlen -= fill;
        left = 0;
    }

    // if message length is greater than or equal to 64
    while (inlen >= 64)
    {
        S->t[0] += 512;

        if (S->t[0] == 0)
            S->t[1]++;

        round_function(S, in);
        in += 64;
        inlen -= 64;
    }

    // if the message when block is empty
    if (inlen > 0)
    {
        memcpy((void*)(S->buf + left), (void*)in, (size_t)inlen);
        S->buflen = left + (int)inlen;
    }
    else
        S->buflen = 0;
}

// finalize blake 256
// calculul lungii finale
void final_block(state256* S, uint8_t* out)
{
    uint8_t msglen[8], zo = 0x01, oo = 0x81; // in msglen punem lungimea mesajului final
    uint32_t lo = S->t[0] + (S->buflen << 3), hi = S->t[1]; // bufflen << 3 inseamna ca din bytes transformati in biti
    // in S->t[0] avem bitii procesati pana acum
    // in S->buflen inseamna cati biti mai sunt in buffer
// deci lo reprezinta cati biti sunt in buffer + cei procesati deja

// space fill is less than greater than 2^32 bits
    if (lo < (S->buflen << 3))
        hi++;

    // get the length of message in 64-bit form
    U32TO8_BIG(msglen + 0, hi);
    U32TO8_BIG(msglen + 4, lo);

    // only one byte for padding is fill
    if (S->buflen == 55)  // avem 55 deoarece din 64 de bytes, 8 sunt pentru lungime si 1 pentru bitul final
        // deci daca avem fix 55, atunci mai incape doar 1 byte inainte de lungime
    {
        S->t[0] -= 8;
        pad_and_round(S, &oo, 1);
    }
    else
    {
        // at least 2 bytes are available for padding
        if (S->buflen < 55) // daca e mai mic decat 55, atunci avem spatiu pentru zerouri, marker, lungime
        {
            // if buflen is 0
            if (!S->buflen)   // daca buflen este 0, atunci blocul final e doar padding
                S->nullt = 1;

            S->t[0] -= 440 - (S->buflen << 3);  // ajusteaza contorul ca si cum ar elimina spatiul pt padding, 440 = 55 bytes * 8 biti
            pad_and_round(S, padding, 55 - S->buflen); //adauga zerouri pana la byte-ul 55
        }
        else // daca este mai mare de 55, atunci se completeaza, se proceseaza si creeaza un nou bloc cu padding + lungime
        {
            S->t[0] -= 512 - (S->buflen << 3);
            pad_and_round(S, padding, 64 - S->buflen);
            S->t[0] -= 440;
            pad_and_round(S, padding + 1, 55);
            S->nullt = 1;
        }

        // add one after padding 0 bits
        pad_and_round(S, &zo, 1);
        S->t[0] -= 8;
    }

    S->t[0] -= 64;
    pad_and_round(S, msglen, 8);

    // converting the 32-bit blocks into 8-bit hash output in big-endian
    U32TO8_BIG(out + 0, S->h[0]);
    U32TO8_BIG(out + 4, S->h[1]);
    U32TO8_BIG(out + 8, S->h[2]);
    U32TO8_BIG(out + 12, S->h[3]);
    U32TO8_BIG(out + 16, S->h[4]);
    U32TO8_BIG(out + 20, S->h[5]);
    U32TO8_BIG(out + 24, S->h[6]);
    U32TO8_BIG(out + 28, S->h[7]);
}

void blake32(uint8_t* out, const uint8_t* in, uint64_t inlen)
{
    state256 S;
    initialize(&S);
    pad_and_round(&S, in, inlen);
    final_block(&S, out);
}


void BLAKE256_COMP(uint8_t* out,
    const uint8_t* H_in,
    const uint8_t* block)
{
    state256 S;
    int i;

    //1️⃣ Inițializare stare
    initialize(&S);

    // 2️⃣ Setăm chaining value extern (H) 
    for (i = 0; i < 8; i++)
        S.h[i] = U8TO32_BIG(H_in + 4 * i);

     // 3️⃣ Dezactivăm contorul și saltul 
    S.t[0] = 0;
    S.t[1] = 0;
    S.nullt = 1;     // IMPORTANT: nu injectăm contorul 

    S.s[0] = 0;
    S.s[1] = 0;
    S.s[2] = 0;
    S.s[3] = 0;

    S.buflen = 0;

    // 4️⃣ Aplicăm o singură compresie pe blocul de 64 bytes 
    round_function(&S, block);

    // 5️⃣ Exportăm noul chaining value 
    for (i = 0; i < 8; i++)
        U32TO8_BIG(out + 4 * i, S.h[i]);
}


int main(int argc, char** argv)
{
    if (argc == 1)
    {
        // lista mesajelor de test
        const char* test_vectors[] = {
            "",
            "0",
            "1234567890",
            "hello world!",
            "!!!@@@###$$$%%%^^^&&&***",
            "The quick brown fox jumps over the lazy dog ",
            "Sa vedem daca acest acest cod da aceeasi valoare de hash de 2 sau mai multe ori",
        };

        // hash-urile așteptate (în hex) - doar ca exemplu, pentru ajay1137 nu avem
        const char* expected_hashes[] = {
            "716f6ef4a4d85aeb3d7a6c14f6db44f934e29eae4f56c63e7e92e0e458df5f87",
            "45343684913a1db5d5c15d6964a9908debd7b58b8fa8cc6d063ee3509bb9776",
            "7c5556cde7f264a8d262db063e66c10af86f7080371a1c7ee7229be382bce8c8",
            "9976ec73b75add61c7ca3a9f70f4866396e9055653aec8800a5056730f3deb3a",
            "5c6671473ea000e1811f9995fe9d9e90f3100e6412b8dd0716b0d8db8729e577",
            "5e18334d52e61de9a12272eb89944a7c74dbf576fbdfb72d94bf85705ff14574",
            "203bce075a4c636c5b0bd30ffea25ec7963889d425a4a8f40385da2d4743bba9"
        };

        int num_tests = 7;  // câte mesaje avem

        for (int t = 0; t < num_tests; t++)
        {
            const char* msg = test_vectors[t];
            uint8_t hash[32];  // aici va fi hash-ul rezultat
            size_t len = strlen(msg);

            // apelăm funcția care calculează hash-ul
            blake32(hash, (const uint8_t*)msg, len);

            // printăm inputul
            printf("Input: \"%s\"\n", msg);

            // printăm hash-ul așteptat
            printf("Expected: %s\n", expected_hashes[t]);

            // printăm hash-ul calculat
            printf("Got     : ");
            for (int i = 0; i < 32; i++)
                printf("%02x", hash[i]);

            printf("\n\n");
        }
    }
    else
    {
        // avem argumente -> procesăm fișiere
        for (int i = 1; i < argc; i++) {
            FILE* fp;
            errno_t err = fopen_s(&fp, argv[i], "rb"); // rb pentru fișiere binare
            if (err != 0 || !fp) {
                printf("Nu s-a putut deschide fisierul: %s\n", argv[i]);
                continue;
            }

            uint8_t out[32];
            state256 S;
            initialize(&S);

            uint8_t buffer[64];
            size_t bytesread;

            while ((bytesread = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
                pad_and_round(&S, buffer, bytesread);
            }

            final_block(&S, out);

            printf("Fisier: %s\nHash : ", argv[i]);
            for (int j = 0; j < 32; j++)
                printf("%02x", out[j]);
            printf("\n\n");

            fclose(fp);
        }

        return 0;
    }
}

*/


