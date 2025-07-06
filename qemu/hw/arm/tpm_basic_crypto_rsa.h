#ifndef __TPM_CRYPTO_RSA__
#define __TPM_CRYPTO_RSA__

#include <stdint.h>
#include <stdbool.h>

#include <openssl/rsa.h>

typedef struct RSAKeyPair {
    EVP_PKEY *pkey;
    uint8_t *public_key_der;
    uint8_t *private_key_der;
    size_t public_key_len;
    size_t private_key_len;
} RSAKeyPair;
RSAKeyPair *qemu_generate_rsa_key(int key_bits);
void free_rsa_keypair(RSAKeyPair *keypair);
//uint64_t rsa_decrypt(uint64_t ciphertext, RSAKey *key);
//bool verify_key_integrity(RSAKey *key);
int qemu_rsa_encrypt(RSAKeyPair *keypair, const uint8_t *plaintext, size_t plaintext_len, uint8_t **ciphertext, size_t *ciphertext_len);
int qemu_rsa_decrypt(RSAKeyPair *keypair, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t **plaintext, size_t *plaintext_len);
int qemu_verify_integrity(RSAKeyPair *keypair);
#endif
