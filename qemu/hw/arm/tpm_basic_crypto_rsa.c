#include "qemu/osdep.h"
#include "qemu/module.h"
#include "crypto/random.h"
#include "crypto/rsakey.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include <stdio.h>
#include "tpm_basic_crypto_rsa.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/bn.h"
#include "openssl/bio.h"

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

static void print_rsa_key_pem(EVP_PKEY *pkey)
{
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

RSAKeyPair *qemu_generate_rsa_key(int key_bits, bool save_to_file, const char *filename_prefix)
{
    RSAKeyPair *keypair;
    
    printf("Generating RSA key pair (%d bits)...\n", key_bits);
    
    keypair = generate_rsa_keypair(key_bits);
    if (!keypair) {
        error_report("Failed to generate RSA keypair");
        return NULL;
    }
    
    printf("RSA key pair generated successfully!\n");
    printf("Public key size: %zu bytes\n", keypair->public_key_len);
    printf("Private key size: %zu bytes\n", keypair->private_key_len);
    
    print_rsa_key_pem(keypair->pkey);
    
    
    return keypair;
}


