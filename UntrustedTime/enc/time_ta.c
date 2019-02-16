/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <assert.h>
#include <stddef.h>
#include <sgx.h>
#include "time.h"
#include "UntrustedTime_t.h"

time_t time(time_t *timer)
{
    __time64_t localTime64;
    sgx_status_t status = ocall_UntrustedTime_time64(&localTime64);

    if (status != SGX_SUCCESS) {
        assert(0);
        return 0;
    }

    if (timer != NULL) {
        *timer = (time_t)localTime64;
    }

    return (time_t)localTime64;
}

struct tm* _gmtime64(const __time64_t *timer)
{
    static GetTm_Result result;

    sgx_status_t status = ocall_UntrustedTime_gmtime64(&result, *timer);
    if ((status != SGX_SUCCESS) || (result.err != 0)) {
        return NULL;
    }
    return (struct tm*)&result.tm;
}

struct tm* _localtime64(const __time64_t *timer)
{
    static GetTm_Result result;

    sgx_status_t status = ocall_UntrustedTime_localtime64(&result, *timer);
    if ((status != SGX_SUCCESS) || (result.err != 0)) {
        return NULL;
    }

    return (struct tm*)&result.tm;
}
