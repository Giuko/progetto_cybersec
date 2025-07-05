#include "qemu/osdep.h"
#include "qemu/module.h"
#include "crypto/random.h"
#include "crypto/rsakey.h"
#include "qapi/error.h"
#include "glib.h"

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
static uint64_t generate_prime(int bits) {
    uint64_t candidate;
    uint8_t random_bytes[8];
    
    do {
        qcrypto_random_bytes(random_bytes, sizeof(random_bytes), NULL);
        candidate = *(uint64_t*)random_bytes;
        
        // Adjust range
        candidate |= (1ULL << (bits - 1)); // MSB = 1
        
        candidate |= 1; // LSB = 1 (if necessary turn even number in off number)
        
    } while (!is_prime(candidate));
    
    return candidate;
}

// Euclide's algorithm to found the modular inverse
static int64_t extended_gcd(int64_t a, int64_t b, int64_t *x, int64_t *y) {
    if (a == 0) {
        *x = 0;
        *y = 1;
        return b;
    }
    
    int64_t x1, y1;
    int64_t gcd_val = extended_gcd(b % a, a, &x1, &y1);
    
    *x = y1 - (b / a) * x1;
    *y = x1;
    
    return gcd_val;
}

static uint64_t mod_inverse(uint64_t a, uint64_t m) {
    int64_t x, y;
    int64_t g = extended_gcd(a, m, &x, &y);
    
    if (g != 1) {
        return 0; // Inverse non existent
    }
    
    return (x % m + m) % m;
}

// Generazione chiavi RSA
bool generate_rsa_keys(TPMRSAContext *ctx, int key_bits) {
    // Generate two prime p e q
    uint64_t p = generate_prime(key_bits / 2);
    uint64_t q = generate_prime(key_bits / 2);
    printf("[TPM]: p and q generated\n"); 
    uint64_t n = p * q;
    
    uint64_t phi_n = (p - 1) * (q - 1);
    
    // e (tipically 65537)
    uint64_t e = 65537;
    if (gcd(e, phi_n) != 1) {
        e = 3; // Fallback
        while (gcd(e, phi_n) != 1) {
            e += 2;
        }
    }
    printf("[TPM]: found greatest common divider between e and phi_n\n");
    
    // Compute d = e^(-1) mod φ(n)
    uint64_t d = mod_inverse(e, phi_n);
    if (d == 0) {
        return false; // Errore nella generazione
    }
    printf("[TPM]: computed d\n");  
    // Save keys
    printf("Public key:  %lx %lx\n", n, e); 
    printf("Private key: %lx %lx\n", n, d); 
    printf("n: %lx (%lu)\n", n, n); 
    printf("d: %lx (%lu)\n", d, d); 
    printf("p: %lx (%lu)\n", p, p); 
    printf("q: %lx (%lu)\n", q, q); 
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
