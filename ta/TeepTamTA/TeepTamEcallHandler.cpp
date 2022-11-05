// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include "Manifest.h"
#include "TeepTamLib.h"
#include "TeepTam_t.h"

int ecall_TamProcessConnect(void* sessionHandle, const char* acceptMediaType)
{
    return TamProcessConnect(sessionHandle, acceptMediaType);
}

int ecall_TamProcessTeepMessage(
    void* sessionHandle,
    const char* mediaType,
    const char* message,
    size_t messageLength)
{
    return TamProcessTeepMessage(
        sessionHandle,
        mediaType,
        message,
        messageLength);
}

teep_error_code_t TamQueueOutboundTeepMessage(
    void* sessionHandle,
    const char* mediaType,
    const char* output_buffer,
    size_t output_buffer_length)
{
    int err;
    oe_result_t result = ocall_TamQueueOutboundTeepMessage((int*)&err, sessionHandle, mediaType, output_buffer, output_buffer_length);
    if (result != OE_OK) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    if (err != OE_OK) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    return TEEP_ERR_SUCCESS;
}