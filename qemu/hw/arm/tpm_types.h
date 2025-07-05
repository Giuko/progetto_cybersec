#ifndef __TPM_TYPES__
#define __TPM_TYPES__
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "tpm_basic_crypto_rsa.h"

/* COMMAND DEFINITION */
/* https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2-Version-184_pub.pdf */
/* 6.5.2 TPM_CC Listing*/
#define TPM2_CC_NV_DefineSpace      0x0000012A
#define TPM2_CC_CreatePrimary       0x00000131 //todo
#define TPM2_CC_Create              0x00000153 //todo
#define TPM2_CC_Load                0x00000157
#define TPM2_CC_Sign                0x0000015F  
#define TPM2_CC_RSA_Encrypt         0x00000174 //todo
#define TPM2_CC_RSA_Decrypt         0x00000159 //todo
#define TPM2_CC_SelfTest            0x00000143 //done
#define TPM2_CC_Startup             0x00000144 //done
#define TPM2_CC_Shutdown            0x00000145 //maybe done
#define TPM2_CC_StartAuthSession    0x00000176
#define TPM2_CC_GetCapability       0x0000017A
#define TPM2_CC_GetRandom           0x0000017B

/* Startup Types */
#define TPM_SU_CLEAR                0x0000 
#define TPM_SU_STATE                0x0001

/* TPM Structure Tag */
#define TPM_ST_NO_SESSION           0x8001
#define TPM_ST_SESSION              0x8002
#define TPM_ST_CREATION             0x8021

/* Response codes */
#define TPM_RC_SUCCESS              0x000

#define TPM_RC_FMT1                 0x080
#define TPM_RC_ASYMMETRIC           (TPM_RC_FMT1 + 0x001)   // Asymmetric algorithm not supported or not correct
#define TPM_RC_VALUE                (TPM_RC_FMT1 + 0x004)   // Bad parameter value
#define TPM_RC_HANDLE               (TPM_RC_FMT1 + 0x00B)   // The Handle in not correct 
#define TPM_RC_SIZE                 (TPM_RC_FMT1 + 0x015)   // Structure is the wrong size

#define TPM_RC_VER1                 0x100
#define TPM_RC_INITIALIZE           (TPM_RC_VER1 + 0x000)   // TPM not initialized
#define TPM_RC_FAILURE              (TPM_RC_VER1 + 0x001)   // Out of memory

#define TPM_RC_WARN                 0x900
#define TPM_RC_TESTING              (TPM_RC_WARN + 0x00A)   // SelfTest Response Code 
#define TPM_RC_OBJECT_MEMORY        (TPM_RC_WARN + 0x002)   // SelfTest Response Code 


/* Key attributes */
typedef enum{
    KEY_TYPE_RSA,
    KEY_TYPE_ECC
} KeyType;

#define FIXED_TPM       0x00000002                // Key cannot be duplicated to another TPM
#define ST_CLEAR        0x00000004                // Key is cleared on TPM Shutdown
#define FIXED_PARENT    0x00000010                // Key's parent handle is fixed
#define DECRYPT         0x00020000                // Key may be used for decrypt operations
#define SIGN            0x00040000                // Key may be used for signature

typedef enum {
    KEY_STATUS_ACTIVE = 0,
    KEY_STATUS_EXPIRED = 1,
    KEY_STATUS_REVOKED = 2,
    KEY_STATUS_SUSPENDED = 3
} key_status;

typedef struct{
    uint32_t handle;
    uint32_t parent_handle;
    KeyType type;
    uint32_t attributes;                    // Bitmap to specifie the key use
   
    TPMRSAContext *ctx;
    
    uint32_t hierarchy;
    bool loaded;

    uint16_t algorithm;
    time_t creation_time;
    time_t last_used;
    uint32_t usage_count;
    uint8_t fingerprint[8];
    key_status status;
}TPM_Key;


/* TPM_RH_HIERARCHY */
#define TPM_RH_OWNER        0x40000001
#define TPM_RH_ENDORSEMENT  0x4000000B
#define TPM_RH_PLATFORM     0x4000000C
#define TPM_RH_NULL         0x40000007

/* TPM ALGORITHM */
#define TPM_ALG_RSA         0x0001
#define TPM_ALG_SHA         0x0003
#define TPM_ALG_SHA1        0x0004
#define TPM_ALG_AES         0x0006
// others... 

/* Begin TPM2B_SENSITIVE_CREATE */
typedef struct {
    uint16_t size;                    // Size of buffer  
    uint8_t buffer[128];               // Additional entropy data
} TPM2B_SENSITIVE_DATA;

typedef struct {
    uint16_t size;                    // Size of buffer
    uint8_t buffer[64];                // Auth value (typically password/PIN)
} TPM2B_AUTH;

typedef struct {
    TPM2B_AUTH userAuth;            // Authorization value for the object
    TPM2B_SENSITIVE_DATA data;      // Extra entropy for key generation
} TPMS_SENSITIVE_CREATE;

typedef struct {
    uint16_t size;                    // Total size of sensitiveCreate
    TPMS_SENSITIVE_CREATE sensitiveCreate;
} TPM2B_SENSITIVE_CREATE;
/* End TPM2B_SENSITIVE_CREATE */

/* Begin TPM2B_PUBLIC */
// Authorization Policy (can be empty)
typedef struct {
    uint16_t size;                  // Size of policy hash
    uint8_t buffer[64];             // Policy hash (usually empty for simple keys)
} TPM2B_DIGEST;
// RSA Public Key
typedef struct {
    uint16_t size;                  // Size of RSA modulus (n)
    uint8_t buffer[512];            // RSA modulus (up to 4096 bits = 512 bytes)
} TPM2B_PUBLIC_KEY_RSA;

typedef struct {
    uint16_t algorithm;             // Symmetric algorithm (TPM_ALG_NULL for RSA)
    uint16_t mode;                  // Mode (not used when algorithm is NULL)
    uint16_t keyBits;               // Key bits (not used when algorithm is NULL)
} TPMT_SYM_DEF_OBJECT;

typedef struct {
    uint16_t scheme;                // RSA scheme (can be TPM_ALG_NULL)
    uint16_t details;               // Scheme details (empty for basic impl)
} TPMT_RSA_SCHEME;

// RSA Parameters Structure
typedef struct {
    TPMT_SYM_DEF_OBJECT symmetric;  // Encryption scheme for keys (usually ALG_NULL)
    TPMT_RSA_SCHEME scheme;         // RSA signature/encryption scheme
    uint16_t keyBits;               // Key size: 1024, 2048, 3072, 4096
    uint32_t exponent;              // Public exponent (0 = default 65537)
} TPMS_RSA_PARMS;

typedef struct {
    uint16_t type;                  // Algorithm type: TPM_ALG_RSA (0x0001)
    uint16_t nameAlg;               // Hash algorithm for object name
    uint32_t objectAttributes;      // Object attributes (32-bit flags)
    TPM2B_DIGEST authPolicy;        // Authorization policy
    TPMS_RSA_PARMS parameters;      // RSA-specific parameters
    TPM2B_PUBLIC_KEY_RSA unique;    // RSA public key (n value)
} TPMT_PUBLIC;

typedef struct {
    uint16_t size;                    // Total size of publicArea
    TPMT_PUBLIC publicArea;
} TPM2B_PUBLIC;

/* End TPM2B_PUBLIC */

#endif //__TPM_TYPES__
