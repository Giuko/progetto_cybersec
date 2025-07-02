#ifndef __TPM_TYPES__
#define __TPM_TYPES__
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

/* COMMAND DEFINITION */
/* https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-2-Version-184_pub.pdf */
/* 6.5.2 TPM_CC Listing*/
#define TPM2_CC_NV_DefineSpace      0x0000012A
#define TPM2_CC_CreatePrimary       0x00000131 //done
#define TPM2_CC_Create              0x00000153 //done
#define TPM2_CC_Load                0x00000157
#define TPM2_CC_Sign                0x0000015F  
#define TPM2_CC_RSA_Encrypt         0x00000174 //done
#define TPM2_CC_RSA_Decrypt         0x00000159 //done
#define TPM2_CC_SelfTest            0x00000143 //done
#define TPM2_CC_Startup             0x00000144 //done
#define TPM2_CC_Shutdown            0x00000145 //done
#define TPM2_CC_StartAuthSession    0x00000176
#define TPM2_CC_GetCapability       0x0000017A
#define TPM2_CC_GetRandom           0x0000017B

/* Peripheral memory region */
#define TPM_BASE_ADDRESS                        ( 0xF0000000UL )
#define TPM_SIZE                                ( 4 * 1024 )

// MACROS to access MMIO
#define mmio_read8(addr) (*(volatile uint8_t *)(addr))
#define mmio_write8(addr, val) (*(volatile uint8_t *)(addr) = (val))

/* TPM Interface Specification Registers */
#define TPM_ACCESS      0x00
#define TPM_STS         0x18
#define TPM_DATA_FIFO   0x24

/* TPM Status Register Flags */
#define TPM_STS_ERROR       0x01        // bit 0
#define TPM_STS_DATA_EXPECT 0x04        // bit 2
#define TPM_STS_DATA_AVAIL  0x10        // bit 4
#define TPM_STS_GO          0x20        // bit 5Add commentMore actions
#define TPM_STS_CMD_READY   0x40        // bit 6
#define TPM_STS_VALID       0x80        // bit 7


/* Hash algorithm sizes */
#define TPM2_SHA_DIGEST_SIZE     20
#define TPM2_SHA1_DIGEST_SIZE    20
#define TPM2_SHA256_DIGEST_SIZE  32
#define TPM2_SHA384_DIGEST_SIZE  48
#define TPM2_SHA512_DIGEST_SIZE  64
#define TPM2_SM3_256_DIGEST_SIZE 32

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
#define TPM2_NUM_PCR_BANKS      16
#define TPM2_MAX_PCRS           32
#define TPM2_PCR_SELECT_MAX      ((TPM2_MAX_PCRS + 7) / 8)
#define TPM2_MAX_RSA_KEY_BYTES  512


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

// typedef struct{
//     uint32_t handle;
//     uint32_t parent_handle;
//     KeyType type;
//     uint32_t attributes;                    // Bitmap to specifie the key use
   
//     TPMRSAContext *ctx;
    
//     uint32_t hierarchy;
//     bool loaded;

//     uint16_t algorithm;
//     time_t creation_time;
//     time_t last_used;
//     uint32_t usage_count;
//     uint8_t fingerprint[8];
//     key_status status;
// }TPM_Key;


/* TPM_RH_HIERARCHY */
#define TPM_RH_OWNER        0x40000001
#define TPM_RH_ENDORSEMENT  0x4000000B
#define TPM_RH_PLATFORM     0x4000000C
#define TPM_RH_NULL         0x40000007

/* TPM ALGORITHM */
#define TPM_ALG_NULL        0x0010
#define TPM_ALG_SHA         0x0004
#define TPM_ALG_SHA1        0x0004
#define TPM_ALG_AES         0x0006
#define TPM_ALG_RSA         0x0001
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

typedef union TPMU_HA TPMU_HA;
union TPMU_HA {
    uint8_t sha [TPM2_SHA_DIGEST_SIZE]; /* TPM2_ALG_SHA */
    uint8_t sha1[TPM2_SHA1_DIGEST_SIZE];
    uint8_t sha256[TPM2_SHA256_DIGEST_SIZE];
    uint8_t sha384[TPM2_SHA384_DIGEST_SIZE];
    uint8_t sha512[TPM2_SHA512_DIGEST_SIZE];
    uint8_t sm3_256[TPM2_SM3_256_DIGEST_SIZE];
};

typedef struct TPM2B_DATA TPM2B_DATA;
struct TPM2B_DATA {
    uint16_t size;
    uint8_t buffer[sizeof(TPMU_HA)];
};

typedef struct TPMS_PCR_SELECTION TPMS_PCR_SELECTION;
struct TPMS_PCR_SELECTION {
    uint16_t hash; /* the hash algorithm associated with the selection */
    uint8_t sizeofSelect; /* the size in octets of the pcrSelect array */
    uint8_t pcrSelect[TPM2_PCR_SELECT_MAX]; /* the bit map of selected PCR */
};

typedef struct TPML_PCR_SELECTION TPML_PCR_SELECTION;
struct TPML_PCR_SELECTION {
    uint32_t count; /* number of selection structures. A value of zero is allowed. */
    TPMS_PCR_SELECTION pcrSelections[TPM2_NUM_PCR_BANKS]; /* list of selections */
};


typedef struct TPM2B_PRIVATE_KEY_RSA TPM2B_PRIVATE_KEY_RSA;
struct TPM2B_PRIVATE_KEY_RSA {
    uint16_t size;
    uint8_t buffer[TPM2_MAX_RSA_KEY_BYTES/2 * 5];
};

typedef union TPMU_SENSITIVE_COMPOSITE TPMU_SENSITIVE_COMPOSITE;
union TPMU_SENSITIVE_COMPOSITE {
    TPM2B_PRIVATE_KEY_RSA rsa;         /* a prime factor of the public key */
};

typedef struct TPMT_SENSITIVE TPMT_SENSITIVE;
struct TPMT_SENSITIVE {
    uint16_t sensitiveType; /* identifier for the sensitive area. This shall be the same as the type parameter of the associated public area. */
    TPM2B_AUTH authValue;          /* user authorization data. The authValue may be a zero-length string. This value shall not be larger than the size of the digest produced by the nameAlg of the object. */
    TPM2B_DIGEST seedValue;        /* for asymmetric key object the optional protection seed for other objects the obfuscation value. This value shall not be larger than the size of the digest produced by nameAlg of the object. */
    TPMU_SENSITIVE_COMPOSITE sensitive; /* the type-specific private data */
};

typedef struct TPM2B_SENSITIVE TPM2B_SENSITIVE;
struct TPM2B_SENSITIVE {
    uint16_t  size;
    TPMT_SENSITIVE sensitiveArea;
};

typedef struct _PRIVATE _PRIVATE;
struct _PRIVATE {
    TPM2B_DIGEST integrityOuter;
    TPM2B_DIGEST integrityInner; /* could also be a TPM2B_IV */
    TPM2B_SENSITIVE sensitive;   /* the sensitive area */
};


typedef struct TPM2B_PRIVATE TPM2B_PRIVATE;
struct TPM2B_PRIVATE {
    uint16_t size;
    uint8_t buffer[sizeof(_PRIVATE)];
};

typedef struct TPMT_HA TPMT_HA;
struct TPMT_HA {
    uint16_t hashAlg; /* selector of the hash contained in the digest that implies the size of the digest. NOTE The leading + on the type indicates that this structure should pass an indication to the unmarshaling function for  so that TPM2_ALG_NULL will be allowed if a use of a TPMT_HA allows TPM2_ALG_NULL. */
    TPMU_HA digest;        /* the digest data */
};

typedef union TPMU_NAME TPMU_NAME;
union TPMU_NAME {
    TPMT_HA digest;     /* when the Name is a digest */
    uint32_t handle; /* when the Name is a handle */
};

typedef struct TPM2B_NAME TPM2B_NAME;
struct TPM2B_NAME {
    uint16_t size;
    uint8_t name[sizeof(TPMU_NAME)];
};

typedef struct TPMS_CREATION_DATA TPMS_CREATION_DATA;
struct TPMS_CREATION_DATA {
    TPML_PCR_SELECTION pcrSelect;   /* done list indicating the PCR included in pcrDigest */
    TPM2B_DIGEST pcrDigest;         /* done digest of the selected PCR using nameAlg of the object for which this structure is being created. pcrDigest.size shall be zero if the pcrSelect list is empty. */
    uint8_t locality;         /*  done the locality at which the object was created */
    uint16_t parentNameAlg;      /* done nameAlg of the parent */
    TPM2B_NAME parentName;          /* done Name of the parent at time of creation. The size will match digest size associated with parentNameAlg unless it is TPM2_ALG_NULL in which case the size will be 4 and parentName will be the hierarchy handle. */
    TPM2B_NAME parentQualifiedName; /* done Qualified Name of the parent at the time of creationSize is the same as parentName. */
    TPM2B_DATA outsideInfo;         /* done association with additional information added by the key creator. This will be the contents of the outsideInfo parameter in TPM2_Create or TPM2_CreatePrimary. */
};

typedef struct TPM2B_CREATION_DATA TPM2B_CREATION_DATA;
struct TPM2B_CREATION_DATA {
    uint16_t  size;
    TPMS_CREATION_DATA creationData;
};

typedef struct TPMT_TK_CREATION TPMT_TK_CREATION;
struct TPMT_TK_CREATION {
    uint16_t tag;                 /* ticket structure tag */
    uint32_t hierarchy; /* the hierarchy containing name */
    TPM2B_DIGEST digest;         //done /* This shall be the HMAC produced using a proof value of hierarchy. */
};

typedef struct TPMS_EMPTY TPMS_EMPTY;
struct TPMS_EMPTY {
    uint8_t empty[1]; /* a structure with no member */
};

typedef TPMS_EMPTY TPMS_ENC_SCHEME_RSAES; 


typedef union TPMU_ASYM_SCHEME TPMU_ASYM_SCHEME;
union TPMU_ASYM_SCHEME {
    TPMS_ENC_SCHEME_RSAES rsaes;         /* schemes with no hash */
};

typedef struct TPMT_RSA_DECRYPT TPMT_RSA_DECRYPT;
struct TPMT_RSA_DECRYPT {
    uint16_t scheme; //done /* scheme selector */
    TPMU_ASYM_SCHEME details;    //done  /* scheme parameters */
};



/* TPM Command Header */
struct tpm_command_header{
    uint16_t tag;
    uint32_t size;
    uint32_t command_code;
} __attribute__((packed));      // To avoid padding

struct tpm_startup_command_header{
    struct tpm_command_header command_header;
    uint16_t startup_type;
} __attribute__((packed));      // To avoid padding

/* TPM Response Header */
struct tpm_response_header{
    uint16_t tag;
    uint32_t size;
    uint32_t response_code;
} __attribute__((packed));      // To avoid padding


/* TMP_create_command*/
struct tpm_create_command{
    struct tpm_command_header command_header;
    //handles
    uint32_t parentHandle;
    //parameters
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
} __attribute__((packed));

/* TMP_create_response*/
struct tpm_create_response{
    struct tpm_response_header response_header;
    //parameters
    TPM2B_PRIVATE outPrivate; //done
    TPM2B_PUBLIC outPublic; //done
    TPM2B_CREATION_DATA creationData; //done
    TPM2B_DIGEST creationHash; //done
    TPMT_TK_CREATION creationTicket; //todo
} __attribute__((packed));

/* TMP_createPrimary_command*/
struct tpm_createPrimary_command{
    struct tpm_command_header command_header; //done
    //handles
    uint32_t primaryHandle; //done
    //parameters
    TPM2B_SENSITIVE_CREATE inSensitive; //done
    TPM2B_PUBLIC inPublic; //done
    TPM2B_DATA outsideInfo; //done
    TPML_PCR_SELECTION creationPCR; //done
} __attribute__((packed));

/* TMP_createPrimary_response*/
struct tpm_createPrimary_response{
    struct tpm_response_header response_header;
    //handles
    uint32_t objectHandle; //done
    //parameters
    TPM2B_PUBLIC outPublic; //done
    TPM2B_CREATION_DATA creationData; //done
    TPM2B_DIGEST creationHash; //done
    TPMT_TK_CREATION creationTicket; //done
} __attribute__((packed));

/* TMP_RSA_encrypt_command*/
struct TMP_RSA_encrypt_command{
    struct tpm_command_header command_header; //done
    //handles
    uint32_t keyHandle; //done
    //parameters
    TPM2B_PUBLIC_KEY_RSA message; //done
    TPMT_RSA_DECRYPT inScheme; //done
    TPM2B_DATA label; //done
} __attribute__((packed));

/* TMP_RSA_encrypt_response*/
struct TMP_RSA_encrypt_response{
    struct tpm_response_header response_header;
    //parameters
    TPM2B_PUBLIC_KEY_RSA outData; //done
} __attribute__((packed));

/* TMP_RSA_decrypt_command*/
struct TMP_RSA_decrypt_command{
    struct tpm_command_header command_header; //done
    //handles
    uint32_t keyHandle; //done
    //parameters
    TPM2B_PUBLIC_KEY_RSA cipherText; //done
    TPMT_RSA_DECRYPT inScheme; //done
    TPM2B_DATA label; //done
} __attribute__((packed));

/* TMP_RSA_decrypt_response*/
struct TMP_RSA_decrypt_response{
    struct tpm_response_header response_header;
    //parameters
    TPM2B_PUBLIC_KEY_RSA message; //done
} __attribute__((packed));


/* TMP_shutdown_command*/
struct TMP_shutdown_command{
    struct tpm_command_header command_header; //done
    uint16_t shutdownType;
} __attribute__((packed));

/* TMP_shutdown_response*/
struct TMP_shutdown_response{
    struct tpm_response_header response_header;
} __attribute__((packed));







enum tpm_state {
    TPM_STATE_IDLE,
    TPM_STATE_READY,
    TPM_STATE_RECEIVING,
    TPM_STATE_PROCESSING,
    TPM_STATE_SENDING
};

/* TPM Interface */
struct tpm_device {
    void *mmio_base;
    uint8_t command_buffer[1024];
    uint8_t response_buffer[1024];
    uint32_t cmd_size;
    uint32_t resp_size;
    enum tpm_state state;
};

/* Basic Function */
void tpm_init(struct tpm_device *dev, void *base_address);

int tpm_send_command(struct tpm_device *dev, void *command, uint32_t size);
int tpm_receive_response(struct tpm_device *dev, void *buffer, uint32_t max_size);


/* Helper and log function */

const char* tpm_command_name(uint32_t command_code);
int tpm_send_command_with_log(struct tpm_device *dev, void *command, uint32_t size);
int tpm_receive_response_with_log(struct tpm_device *dev, void *buffer, uint32_t max_size);
void log_tpm_status(struct tpm_device *dev);
#endif
