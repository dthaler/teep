#ifndef OTRPDEVICE_U_H__
#define OTRPDEVICE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_SendOTrPMessage, (const char* message, int messageLength));

sgx_status_t ecall_ProcessOTrPMessage(sgx_enclave_id_t eid, int* retval, const char* message, int messageLength);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
