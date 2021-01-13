#ifndef AES_NI_H
#define AES_NI_H

#include <wmmintrin.h>

/**
 * @brief The key expansion routine for encryption. Unless one calls AES128_loadKey() must be called before AES128_encrypt(). 
 * 
 * @param expandedKey Pointer to the allocated memory, where the expanded key will be stored. One must allocate memory for at least 11 elements.
 * @param key The encryption key.
 */
void AES128_loadEncryptionKeyOnly(__m128i* expandedKey, const unsigned char* key);
/**
 * @brief The key expansion routine for encryption and decryption. Must be called before AES128_decrypt(). Calls AES128_loadEncryptionKeyOnly() internally.
 * 
 * @param expandedKey Pointer to the allocated memory, where expanded key will be stored. One must allocate memory for at least 20 elements.
 * @param key The encryption/decryption key.
 */
void AES128_loadKey(__m128i* expandedKey, const unsigned char* key);
/**
 * @brief The encryption algorithm. AES128_loadEncryptionKeyOnly() or AES128_loadKey() must be called beforehand. 
 * 
 * @param ciphertext Pointer to the allocated memory, where the ciphertext will be stored. One must allocate memory for at least 16 elements.
 * @param plaintext The text to encrypt.
 * @param expandedKey The expanded key, calculated beforehand with AES128_loadEncryptionKeyOnly() or AES128_loadKey().
 */
void AES128_encrypt(unsigned char* ciphertext, const unsigned char* plaintext, const __m128i* expandedKey);
/**
 * @brief The decryption algorithm. AES128_loadKey() must be called beforehand.
 * 
 * @param plaintext Pointer to the allocated memory, where the plaintext will be stored. One must allocate memory for at least 16 elements.
 * @param ciphertext The text to decrypt.
 * @param expandedKey The expanded key, calculated beforehand with AES128_loadKey().
 */
void AES128_decrypt(unsigned char* plaintext, const unsigned char* ciphertext, const __m128i* expandedKey);

#endif