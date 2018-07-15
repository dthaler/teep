#include "OTrPDevice_u.h"
#include <errno.h>

typedef struct ms_ecall_ProcessOTrPMessage_t {
	int ms_retval;
	char* ms_message;
	int ms_messageLength;
} ms_ecall_ProcessOTrPMessage_t;

typedef struct ms_ocall_SendOTrPMessage_t {
	int ms_retval;
	char* ms_message;
	int ms_messageLength;
} ms_ocall_SendOTrPMessage_t;

static sgx_status_t SGX_CDECL OTrPDevice_ocall_SendOTrPMessage(void* pms)
{
	ms_ocall_SendOTrPMessage_t* ms = SGX_CAST(ms_ocall_SendOTrPMessage_t*, pms);
	ms->ms_retval = ocall_SendOTrPMessage((const char*)ms->ms_message, ms->ms_messageLength);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[1];
} ocall_table_OTrPDevice = {
	1,
	{
		(void*)(uintptr_t)OTrPDevice_ocall_SendOTrPMessage,
	}
};

sgx_status_t ecall_ProcessOTrPMessage(sgx_enclave_id_t eid, int* retval, const char* message, int messageLength)
{
	sgx_status_t status;
	ms_ecall_ProcessOTrPMessage_t ms;
	ms.ms_message = (char*)message;
	ms.ms_messageLength = messageLength;
	status = sgx_ecall(eid, 0, &ocall_table_OTrPDevice, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

