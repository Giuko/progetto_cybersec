#include "qemu/osdep.h"
#include "qemu/module.h"
#include "crypto/random.h"
#include "crypto/rsakey.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include <stdio.h>
#include "tpm_basic_crypto_rsa.h"


static RSAKeyPair *generate_rsa_keypair(int key_bits){
    RSAKeyPair *keypair = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    keypair = g_malloc0(sizeof(RSAKeyPair));
    if (!keypair) {
        error_report("Failed to allocate memory for RSA keypair");
        return NULL;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        error_report("Failed to create EVP_PKEY_CTX");
        goto error;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        error_report("Failed to initialize key generation");
        goto error;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_bits) <= 0) {
        error_report("Failed to set RSA key bits");
        goto error;
    }

    if (EVP_PKEY_keygen(ctx, &keypair->pkey) <= 0) {
        error_report("Failed to generate RSA key");
        goto error;
    }

    keypair->public_key_len = i2d_PUBKEY(keypair->pkey, &keypair->public_key_der);
    if (keypair->public_key_len <= 0) {
        error_report("Failed to extract public key");
        goto error;
    }

    keypair->private_key_len = i2d_PrivateKey(keypair->pkey, &keypair->private_key_der);
    if (keypair->private_key_len <= 0) {
        error_report("Failed to extract private key");
        goto error;
    }

    EVP_PKEY_CTX_free(ctx);
    return keypair;

error:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (keypair) {
        if (keypair->pkey) EVP_PKEY_free(keypair->pkey);
        if (keypair->public_key_der) OPENSSL_free(keypair->public_key_der);
        if (keypair->private_key_der) OPENSSL_free(keypair->private_key_der);
        g_free(keypair);
    }
    return NULL;
}

static void print_rsa_key_pem(EVP_PKEY *pkey){
    BIO *bio_out = BIO_new(BIO_s_mem());
    char *key_data;
    long key_len;
    
    if (!bio_out) {
        error_report("Failed to create BIO for key output");
        return;
    }
    
    /* Stampa chiave pubblica */
    printf("=== RSA PUBLIC KEY ===\n");
    if (PEM_write_bio_PUBKEY(bio_out, pkey)) {
        key_len = BIO_get_mem_data(bio_out, &key_data);
        printf("%.*s\n", (int)key_len, key_data);
    }
    
    /* Reset BIO */
    BIO_reset(bio_out);
    
    /* Stampa chiave privata */
    printf("=== RSA PRIVATE KEY ===\n");
    if (PEM_write_bio_PrivateKey(bio_out, pkey, NULL, NULL, 0, NULL, NULL)) {
        key_len = BIO_get_mem_data(bio_out, &key_data);
        printf("%.*s\n", (int)key_len, key_data);
    }
    
    BIO_free(bio_out);
}

RSAKeyPair *qemu_generate_rsa_key(int key_bits){
    RSAKeyPair *keypair;
    
    printf("[TPM] Generating RSA key pair (%d bits)...\n", key_bits);
    
    keypair = generate_rsa_keypair(key_bits);
    if (!keypair) {
        error_report("[TPM] Failed to generate RSA keypair");
        return NULL;
    }
    
    printf("[TPM] RSA key pair generated successfully!\n");
    printf("[TPM] Public key size: %zu bytes\n", keypair->public_key_len);
    printf("[TPM] Private key size: %zu bytes\n", keypair->private_key_len);
    
    // print_rsa_key_pem(keypair->pkey);
 
    if(!qemu_verify_integrity(keypair)){
        printf("Verification failed\n");
        return NULL;
    }
    
    return keypair;
}


int qemu_rsa_encrypt(RSAKeyPair *keypair, const uint8_t *plaintext, size_t plaintext_len, uint8_t **ciphertext, size_t *ciphertext_len){
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;
    
    if (!keypair || !keypair->pkey || !plaintext || !ciphertext || !ciphertext_len) {
        error_report("[TPM]: Invalid parameters for RSA encryption");
        return -1;
    }
    
    ctx = EVP_PKEY_CTX_new(keypair->pkey, NULL);
    if (!ctx) {
        error_report("[TPM]: Failed to create encryption context");
        return -1;
    }
    
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        error_report("[TPM]: Failed to initialize encryption");
        goto cleanup;
    }
    
    /* Set padding PKCS#1 v1.5 */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        error_report("[TPM]: Failed to set RSA padding");
        goto cleanup;
    }
    
    if (EVP_PKEY_encrypt(ctx, NULL, ciphertext_len, plaintext, plaintext_len) <= 0) {
        error_report("[TPM]: Failed to determine ciphertext length");
        goto cleanup;
    }
    
    *ciphertext = g_malloc(*ciphertext_len);
    if (!*ciphertext) {
        error_report("[TPM]: Failed to allocate memory for ciphertext");
        goto cleanup;
    }
    
    if (EVP_PKEY_encrypt(ctx, *ciphertext, ciphertext_len, plaintext, plaintext_len) <= 0) {
        error_report("[TPM]: Failed to encrypt data");
        g_free(*ciphertext);
        *ciphertext = NULL;
        goto cleanup;
    }
    
    printf("[TPM]: RSA encryption successful: %zu bytes -> %zu bytes\n", plaintext_len, *ciphertext_len);
    ret = 0;
    
cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

int qemu_rsa_decrypt(RSAKeyPair *keypair, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t **plaintext, size_t *plaintext_len){
EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;
    
    if (!keypair || !keypair->pkey || !ciphertext || !plaintext || !plaintext_len) {
        error_report("[TPM]: Invalid parameters for RSA decryption");
        return -1;
    }
    
    ctx = EVP_PKEY_CTX_new(keypair->pkey, NULL);
    if (!ctx) {
        error_report("[TPM]: Failed to create decryption context");
        return -1;
    }
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        error_report("[TPM]: Failed to initialize decryption");
        goto cleanup;
    }
    
    /* Set padding PKCS#1 v1.5 */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        error_report("[TPM]: Failed to set RSA padding");
        goto cleanup;
    }
    
    if (EVP_PKEY_decrypt(ctx, NULL, plaintext_len, ciphertext, ciphertext_len) <= 0) {
        error_report("[TPM]: Failed to determine plaintext length");
        goto cleanup;
    }
    
    *plaintext = g_malloc(*plaintext_len);
    if (!*plaintext) {
        error_report("[TPM]: Failed to allocate memory for plaintext");
        goto cleanup;
    }
    
    if (EVP_PKEY_decrypt(ctx, *plaintext, plaintext_len, ciphertext, ciphertext_len) <= 0) {
        error_report("[TPM]: Failed to decrypt data");
        g_free(*plaintext);
        *plaintext = NULL;
        goto cleanup;
    }
    
    printf("[TPM]: RSA decryption successful: %zu bytes -> %zu bytes\n", ciphertext_len, *plaintext_len);
    ret = 0;
    
cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

int qemu_verify_integrity(RSAKeyPair *keypair){
    const char *test_data = "RSA encryption/decryption test";
    uint8_t *ciphertext = NULL, *decrypted = NULL;
    size_t ciphertext_len = 0, decrypted_len = 0;
    uint8_t outcome = 0; 
    printf("\n=== RSA Verification Test ===\n");
    printf("[TPM]: Original data: '%s'\n", test_data);
    
    /* Test PKCS#1 v1.5 padding */
    if (qemu_rsa_encrypt(keypair, (uint8_t *)test_data, strlen(test_data), 
                         &ciphertext, &ciphertext_len) == 0) {
        
        printf("[TPM]: Encrypted data: %.*s\n", (int)ciphertext_len, ciphertext);
        if (qemu_rsa_decrypt(keypair, ciphertext, ciphertext_len, 
                             &decrypted, &decrypted_len) == 0) {
            printf("[TPM]: Decrypted data: %.*s\n", (int)decrypted_len, decrypted);
            
            if (decrypted_len == strlen(test_data) && 
                memcmp(decrypted, test_data, decrypted_len) == 0) {
                printf("[TPM]: encryption/decryption successful!\n");
                outcome = 1;
            } else {
                printf("[TPM]: Decryption mismatch!\n");
                outcome = 0;
            }
        }
    }
    
    /* Cleanup */
    if (ciphertext) g_free(ciphertext);
    if (decrypted) g_free(decrypted);
    return outcome;
}
