
#include <stdint.h>
#include "stdbool.h"
#include "tpm.h"


#define TPM_STS_VALID       (1 << 7)   // stsValid, if 0 the STS should be ignore
#define TPM_STS_DATA_AVAIL  (1 << 4)   // dataAvail, if 1 you can read
#define TPM_STS_EXPECT      (1 << 3)   // tpmExpect, if 0 writing the FIFO is invalid 

void TPM_write(uint8_t data){
    while( ((TPM_STS & TPM_STS_VALID) == 0) || (TPM_STS & TPM_STS_EXPECT) == 0){}

    // It is possible to write
    TPM_DATA_FIFO = data;
}

uint8_t TPM_read(void){
    while( ((TPM_STS & TPM_STS_VALID) == 0) || (TPM_STS & TPM_STS_DATA_AVAIL) == 0){}
    return TPM_DATA_FIFO;
}


//////////////////////
// Access Register
/////////////////////
#define TPM_ACCESS_RegValidSts      (1 << 7)    // If 1 then all other bits of this register contain valid values
#define TPM_ACCESS_activeLocality   (1 << 5)    // Read 0 if this isn't active, Read 1 if it is active, Write 1 if want the control
#define TPM_ACCESS_beenSeized       (1 << 4)    // Read 0 if it works normallyor is not active
                                                // Read 1 if control of the TPM has been taken from this locality by another 
                                                //          higher locality while this locality had its 
                                                //          TPM_ACCESS_x.activeLocality bit set
                                                // Write 1 to clear the bit
#define TPM_ACCESS_Seize            (1 << 3)    // A write to this field forces the TPM to give control of the 
                                                //          TPM to the localtiy setting this bit if it
                                                //          is the higher priority locality.
#define TPM_ACCESS_pendingRequest   (1 << 2)    // Read 1 = some other locality is requesting usage of the TPM
                                                // Read 0 = no other locality is requesting use of the TPM
#define TPM_ACCESS_requestUse       (1 << 1)    // Read 0 = This locality is either not requesting to use the 
                                                //          TPM or is already the active locality
                                                // Read 1 = This locality is requesting to use TPM and is 
                                                //          not yet the active locality
                                                // Write 1 = Request that this locality is granted the active locality
#define TPM_ACCESS_establishment    (1 << 0)    //


void TPM_GainOwnership(void){
    TPM_ACCESS = TPM_ACCESS_requestUse;
    while((TPM_ACCESS & TPM_ACCESS_activeLocality) == 0){
        // WAIT
    }
}
