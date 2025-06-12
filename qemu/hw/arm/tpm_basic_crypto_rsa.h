#ifndef __TPM_CRYPTO_RSA__
#define __TPM_CRYPTO_RSA__

#include <stdint.h>
#include <stdbool.h>

// RSA key structure
typedef struct {
    uint64_t n;      // module
    uint64_t e;      // pubblico part
    uint64_t d;      // privato part
    uint64_t p, q;   // prime factor
    bool is_valid;
} RSAKey;

typedef struct {
    RSAKey public_key;
    RSAKey private_key;
    uint32_t key_size;
    bool keys_generated;
} TPMRSAContext;

bool generate_rsa_keys(TPMRSAContext *ctx, int key_bits);
uint64_t rsa_encrypt(uint64_t message, RSAKey *key); 
uint64_t rsa_decrypt(uint64_t ciphertext, RSAKey *key);
bool verify_key_integrity(RSAKey *key);

#endif
