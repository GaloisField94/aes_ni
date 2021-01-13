#include "aes_ni.h"

#define RC_0 0x01
#define RC_1 0x02
#define RC_2 0x04
#define RC_3 0x08
#define RC_4 0x10
#define RC_5 0x20
#define RC_6 0x40
#define RC_7 0x80
#define RC_8 0x1B
#define RC_9 0x36


#define nextRoundKey(k, RC) nextRoundKeyF(k, _mm_aeskeygenassist_si128(k, RC)) //unfortunately _mm_aeskeygenassist_si128 can't be used otherwise: 'the last argument must be an 8-bit immediate'
static inline __m128i nextRoundKeyF(__m128i roundKey, __m128i precomputation) {
    precomputation = _mm_shuffle_epi32(precomputation, _MM_SHUFFLE(3, 3, 3, 3));
    roundKey = _mm_xor_si128(roundKey, _mm_slli_si128(roundKey, 4));
    roundKey = _mm_xor_si128(roundKey, _mm_slli_si128(roundKey, 4));
    roundKey = _mm_xor_si128(roundKey, _mm_slli_si128(roundKey, 4));
    return _mm_xor_si128(roundKey, precomputation);
}

inline void AES128_loadEncryptionKeyOnly(__m128i* expandedKey, const unsigned char* key) {
    expandedKey[0] = _mm_loadu_si128((__m128i*) key);
    expandedKey[1] = nextRoundKey(expandedKey[0], RC_0);
    expandedKey[2] = nextRoundKey(expandedKey[1], RC_1);
    expandedKey[3] = nextRoundKey(expandedKey[2], RC_2);
    expandedKey[4] = nextRoundKey(expandedKey[3], RC_3);
    expandedKey[5] = nextRoundKey(expandedKey[4], RC_4);
    expandedKey[6] = nextRoundKey(expandedKey[5], RC_5);
    expandedKey[7] = nextRoundKey(expandedKey[6], RC_6);
    expandedKey[8] = nextRoundKey(expandedKey[7], RC_7);
    expandedKey[9] = nextRoundKey(expandedKey[8], RC_8);
    expandedKey[10] = nextRoundKey(expandedKey[9], RC_9);
}

//decryption algorithm round function is not implemented exactly as described in FIPS 197
//instead it's an equivalent descripted in "The Design of Rijndael" and requires an equivalent form of expanded key
//I recommend reading the book if you're interested why it's been done this way (spoiler - efficiency on 32 and more bit platforms) 
inline void AES128_loadKey(__m128i* expandedKey, const unsigned char* key) {
    AES128_loadEncryptionKeyOnly(expandedKey, key);
    expandedKey[19] = _mm_aesimc_si128(expandedKey[1]);
    expandedKey[18] = _mm_aesimc_si128(expandedKey[2]);
    expandedKey[17] = _mm_aesimc_si128(expandedKey[3]);
    expandedKey[16] = _mm_aesimc_si128(expandedKey[4]);
    expandedKey[15] = _mm_aesimc_si128(expandedKey[5]);
    expandedKey[14] = _mm_aesimc_si128(expandedKey[6]);
    expandedKey[13] = _mm_aesimc_si128(expandedKey[7]);
    expandedKey[12] = _mm_aesimc_si128(expandedKey[8]);
    expandedKey[11] = _mm_aesimc_si128(expandedKey[9]);
}

inline void AES128_encrypt(unsigned char* ciphertext, const unsigned char* plaintext, const __m128i* expandedKey) {
    __m128i state = _mm_loadu_si128((__m128i*) plaintext);

    state = _mm_xor_si128(state, expandedKey[0]);
    state = _mm_aesenc_si128(state, expandedKey[1]);
    state = _mm_aesenc_si128(state, expandedKey[2]);
    state = _mm_aesenc_si128(state, expandedKey[3]);
    state = _mm_aesenc_si128(state, expandedKey[4]);
    state = _mm_aesenc_si128(state, expandedKey[5]);
    state = _mm_aesenc_si128(state, expandedKey[6]);
    state = _mm_aesenc_si128(state, expandedKey[7]);
    state = _mm_aesenc_si128(state, expandedKey[8]);
    state = _mm_aesenc_si128(state, expandedKey[9]);
    state = _mm_aesenclast_si128(state, expandedKey[10]);

    _mm_storeu_si128((__m128i*) ciphertext, state);
}

inline void AES128_decrypt(unsigned char* plaintext, const unsigned char* ciphertext, const __m128i* expandedKey) {
    __m128i state = _mm_loadu_si128((__m128i*) ciphertext);

    state = _mm_xor_si128(state, expandedKey[10]);
    state = _mm_aesdec_si128(state, expandedKey[11]);
    state = _mm_aesdec_si128(state, expandedKey[12]);
    state = _mm_aesdec_si128(state, expandedKey[13]);
    state = _mm_aesdec_si128(state, expandedKey[14]);
    state = _mm_aesdec_si128(state, expandedKey[15]);
    state = _mm_aesdec_si128(state, expandedKey[16]);
    state = _mm_aesdec_si128(state, expandedKey[17]);
    state = _mm_aesdec_si128(state, expandedKey[18]);
    state = _mm_aesdec_si128(state, expandedKey[19]);
    state = _mm_aesdeclast_si128(state, expandedKey[0]);

    _mm_storeu_si128((__m128i*) plaintext, state);
}