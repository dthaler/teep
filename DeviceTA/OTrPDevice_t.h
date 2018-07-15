#ifndef OTRPDEVICE_T_H__
#define OTRPDEVICE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


int ecall_ProcessOTrPMessage(const char* message, int messageLength);

sgx_status_t SGX_CDECL ocall_SendOTrPMessage(int* retval, const char* message, int messageLength);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
