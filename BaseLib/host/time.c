/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include "BaseLib_u.h"
#include <time.h>

uint64_t ocall_time64(void)
{
    uint64_t t;
    _time64((__time64_t*)&t);
    return t;
}

GetTm_Result ocall_localtime64(uint64_t timer)
{
    GetTm_Result result;
    result.err = _localtime64_s((struct tm*)&result.tm, (const __time64_t*)&timer);
    return result;
}

GetTm_Result ocall_gmtime64(uint64_t timer)
{
    GetTm_Result result;
    result.err = _gmtime64_s((struct tm*)&result.tm, (const __time64_t*)&timer);
    return result;
}