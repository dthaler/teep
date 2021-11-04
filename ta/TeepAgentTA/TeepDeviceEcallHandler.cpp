// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <openenclave/enclave.h>
#include "TeepAgent_t.h"
#include "TeepDeviceEcallHandler.h"
#include "TeepAgentLib.h"
#include "common.h"

int ecall_RequestTA(int useCbor, oe_uuid_t requestedTaid, const char* tamUri)
{
    return TeepAgentRequestTA(useCbor, requestedTaid, tamUri);
}

int ecall_UnrequestTA(int useCbor, oe_uuid_t unneededTaid, const char* tamUri)
{
    return TeepAgentUnrequestTA(useCbor, unneededTaid, tamUri);
}

int ecall_ProcessError(void* sessionHandle)
{
    return TeepAgentProcessError(sessionHandle);
}

int ecall_RequestPolicyCheck(const char* tamUri)
{
    return TeepAgentRequestPolicyCheck(tamUri);
}

int Connect(
    const char* tamUri,
    const char* acceptMediaType)
{
    teep_error_code_t err;
    oe_result_t result = ocall_Connect((int*)&err, tamUri, acceptMediaType);
    if (result != OE_OK) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    return err;
}