#include "qemu/osdep.h"
#include "qemu/module.h"
#include "crypto/random.h"
#include "crypto/rsakey.h"
#include "qapi/error.h"
#include "glib.h"
#include <stdio.h>
#include "tpm_basic_crypto_rsa.h"

// greatest common divider
static uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

static uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base = base % mod;
    
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

static bool is_prime(uint64_t n) {
    if (n < 2) return false;            // 1 and 0 not prime
    if (n == 2 || n == 3) return true;  // 2 and 3 prime
    if (n % 2 == 0) return false;       // even number not prime
    
    for (uint64_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return false;
    }
    return true;
}

// QEMU random number generation
static uint32_t generate_prime(int bits) {
    uint32_t candidate;
    uint8_t random_bytes[4];
    
    do {
        qcrypto_random_bytes(random_bytes, sizeof(random_bytes), NULL);
        candidate = *(uint32_t*)random_bytes;
        
        // Adjust range
        candidate |= (1ULL << (bits - 1)); // MSB = 1
        
        candidate |= 1; // LSB = 1 (if necessary turn even number in off number)
        
    } while (!is_prime(candidate));
    
    return candidate;
}

// Algorithm to found the modular inverse
uint64_t modinv(uint64_t e, uint64_t phi_n) {
    int64_t t = 0, new_t = 1;
    int64_t r = phi_n, new_r = e;

    while (new_r != 0) {
        int64_t quotient = r / new_r;

        int64_t temp_t = t;
        t = new_t;
        new_t = temp_t - quotient * new_t;

        int64_t temp_r = r;
        r = new_r;
        new_r = temp_r - quotient * new_r;
    }

    // Check if inverse exists
    if (r > 1) {
        return 0; // e and phi_n are not coprime
    }

    if (t < 0) {
        t += phi_n;
    }

    return (uint64_t)t;
}

// Generazione chiavi RSA
bool generate_rsa_keys(TPMRSAContext *ctx, int key_bits) {
    // Generate two prime p e q
    uint32_t p = generate_prime(32);
    uint32_t q = generate_prime(32);
    printf("[TPM]: p and q generated\n"); 
    uint64_t n = (uint64_t)p * (uint64_t)q;
    
    uint64_t phi_n = (uint64_t)(p-1) * (uint64_t)(q-1);
    
    // e (tipically 65537)
    uint64_t e = 65537;
    if (gcd(e, phi_n) != 1) {
        e = 3; // Fallback
        while (gcd(e, phi_n) != 1) {
            e += 2;
        }
    }
    
    // Compute d = e^(-1) mod φ(n)
    //uint64_t d = mod_inverse(e, phi_n);
    uint64_t d = modinv(e, phi_n);
    if (d == 0) {
        //return false; // Errore nella generazione
        printf("d==0\n");
    }
    // Save keys
    printf("Public key:  %lx %lx\n", n, e); 
    printf("Private key: %lx %lx\n", n, d); 
    printf("n: %lx (%lu)\n", n, n); 
    printf("d: %lx (%lu)\n", d, d); 
    printf("p: %x (%u)\n", p, p); 
    printf("q: %x (%u)\n", q, q); 
    printf("e: %lx (%lu)\n", e, e); 
    printf("phi_n: %lx (%lu)\n", phi_n, phi_n); 
    ctx->public_key.n = n;
    ctx->public_key.e = e;
    ctx->public_key.p = p;
    ctx->public_key.q = q; 
    ctx->public_key.is_valid = true;
    printf("[TPM]: public_key generated\n"); 
    ctx->private_key.n = n;
    ctx->private_key.d = d;
    ctx->private_key.p = p;
    ctx->private_key.q = q;
    ctx->private_key.is_valid = true; 
    printf("[TPM]: private_key generated\n");
    
    ctx->key_size = key_bits;
    ctx->keys_generated = true;
    printf("[TPM]: key generated\n");   
    return true;
}

// Basic crypto operations
uint64_t rsa_encrypt(uint64_t message, RSAKey *key) {
    return mod_exp(message, key->e, key->n);
}

uint64_t rsa_decrypt(uint64_t ciphertext, RSAKey *key) {
    return mod_exp(ciphertext, key->d, key->n);
}

bool verify_key_integrity(RSAKey *key) {
    if (!key->is_valid) {
        return false;
    }
    
    // Test con messaggio di prova
    uint64_t test_msg = key->n - 1;
    
    uint64_t encrypted = rsa_encrypt(test_msg, key);
    uint64_t decrypted = rsa_decrypt(encrypted, key);
    
    return (decrypted == test_msg);
}
