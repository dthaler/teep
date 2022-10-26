// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include <openenclave/enclave.h>
#include "TeepCommonTALib_t.h"
#include "teep_protocol.h"
#include "common.h"

teep_error_code_t QueueOutboundTeepMessage(
    void* sessionHandle,
    const char* mediaType,
    const char* output_buffer,
    size_t output_buffer_length)
{
    int err;
    oe_result_t result = ocall_QueueOutboundTeepMessage((int*)&err, sessionHandle, mediaType, output_buffer, output_buffer_length);
    if (result != OE_OK) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    if (err != OE_OK) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    return TEEP_ERR_SUCCESS;
}

teep_error_code_t teep_random(void* buffer, size_t length)
{
    oe_result_t result = oe_random(buffer, length);
    return (result == OE_OK) ? TEEP_ERR_SUCCESS : TEEP_ERR_TEMPORARY_ERROR;
}