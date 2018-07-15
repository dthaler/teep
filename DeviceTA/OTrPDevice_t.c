#include "OTrPDevice_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_ecall_ProcessOTrPMessage(void* pms)
{
	ms_ecall_ProcessOTrPMessage_t* ms = SGX_CAST(ms_ecall_ProcessOTrPMessage_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_message = ms->ms_message;
	int _tmp_messageLength = ms->ms_messageLength;
	size_t _len_message = _tmp_messageLength;
	char* _in_message = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ProcessOTrPMessage_t));
	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);

	if (_tmp_message != NULL) {
		_in_message = (char*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_message, _tmp_message, _len_message);
	}
	ms->ms_retval = ecall_ProcessOTrPMessage((const char*)_in_message, _tmp_messageLength);
err:
	if (_in_message) free((void*)_in_message);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_ecall_ProcessOTrPMessage, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][1];
} g_dyn_entry_table = {
	1,
	{
		{0, },
	}
};


sgx_status_t SGX_CDECL ocall_SendOTrPMessage(int* retval, const char* message, int messageLength)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_message = messageLength;

	ms_ocall_SendOTrPMessage_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_SendOTrPMessage_t);
	void *__tmp = NULL;

	ocalloc_size += (message != NULL && sgx_is_within_enclave(message, _len_message)) ? _len_message : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_SendOTrPMessage_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_SendOTrPMessage_t));

	if (message != NULL && sgx_is_within_enclave(message, _len_message)) {
		ms->ms_message = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_message);
		memcpy((void*)ms->ms_message, message, _len_message);
	} else if (message == NULL) {
		ms->ms_message = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_messageLength = messageLength;
	status = sgx_ocall(0, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
