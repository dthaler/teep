// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <openenclave/enclave.h>
#include "TeepAgent_t.h"
#include "TeepDeviceEcallHandler.h"
#include "TeepAgentLib.h"
#include "common.h"

int ecall_TeepAgentRequestTA(oe_uuid_t requestedTaid, const char* tamUri)
{
    return TeepAgentRequestTA(requestedTaid, tamUri);
}

int ecall_TeepAgentUnrequestTA(oe_uuid_t unneededTaid, const char* tamUri)
{
    return TeepAgentUnrequestTA(unneededTaid, tamUri);
}

int ecall_TeepAgentProcessError(void* sessionHandle)
{
    return TeepAgentProcessError(sessionHandle);
}

int ecall_TeepAgentRequestPolicyCheck(const char* tamUri)
{
    return TeepAgentRequestPolicyCheck(tamUri);
}

int ecall_TeepAgentProcessTeepMessage(
    void* sessionHandle,
    const char* mediaType,
    const char* message,
    size_t messageLength)
{
    return TeepAgentProcessTeepMessage(
        sessionHandle,
        mediaType,
        message,
        messageLength);
}

int ecall_TeepAgentLoadConfiguration(const char* dataDirectory)
{
    return TeepAgentLoadConfiguration(dataDirectory);
}

int ecall_TeepAgentInitializeKeys(const char* dataDirectory, char publicKeyFilename[256])
{
    return TeepAgentInitializeKeys(dataDirectory, publicKeyFilename);
}

teep_error_code_t TeepAgentConnect(
    _In_z_ const char* tamUri,
    _In_z_ const char* acceptMediaType)
{
    teep_error_code_t err;
    oe_result_t result = ocall_TeepAgentConnect((int*)&err, tamUri, acceptMediaType);
    if (result != OE_OK) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    return err;
}

teep_error_code_t TeepAgentQueueOutboundTeepMessage(
    void* sessionHandle,
    const char* mediaType,
    const char* output_buffer,
    size_t output_buffer_length)
{
    int err;
    oe_result_t result = ocall_TeepAgentQueueOutboundTeepMessage((int*)&err, sessionHandle, mediaType, output_buffer, output_buffer_length);
    if (result != OE_OK) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    if (err != OE_OK) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    return TEEP_ERR_SUCCESS;
}