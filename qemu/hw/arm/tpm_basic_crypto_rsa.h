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

RSAKeyPair *qemu_generate_rsa_key(int key_bits, bool save_to_file, const char *filename_prefix);
void free_rsa_keypair(RSAKeyPair *keypair);

//uint64_t rsa_encrypt(uint64_t message, RSAKey *key); 
//uint64_t rsa_decrypt(uint64_t ciphertext, RSAKey *key);
//bool verify_key_integrity(RSAKey *key);

#endif
