// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include <openenclave/host.h>
#include "TeepTamBrokerLib.h"

// TODO: investigate why it links with this line
// but has undefined symbols without it.
#define ecall_Initialize TeepTam_ecall_Initialize
#include "TeepTam_u.h"

oe_enclave_t* g_ta_eid = NULL;

// Forward an incoming TEEP message, which might be from any session.
teep_error_code_t TamProcessTeepMessage(
    _In_ void* sessionHandle,
    _In_z_ const char* mediaType,
    _In_reads_(messageLength) const char* message,
    size_t messageLength)
{
    teep_error_code_t err;
    oe_result_t result = ecall_TamProcessTeepMessage(g_ta_eid, (int*)&err, sessionHandle, mediaType, message, messageLength);
    if (result != OE_OK) {
        return TEEP_ERR_PERMANENT_ERROR;
    }
    return err;
}

teep_error_code_t TamProcessConnect(_In_ void* sessionHandle, _In_z_ const char* acceptMediaType)
{
    teep_error_code_t err;
    oe_result_t result = ecall_ProcessTeepConnect(g_ta_eid, (int*)&err, sessionHandle, acceptMediaType);
    if (result != OE_OK) {
        return TEEP_ERR_PERMANENT_ERROR;
    }
    return err;
}

int TeepInitialize(void)
{
    return ecall_Initialize(g_ta_eid);
}

int ocall_TamQueueOutboundTeepMessage(void* sessionHandle, const char* mediaType, const char* message, size_t messageLength)
{
    return TamQueueOutboundTeepMessage(sessionHandle, mediaType, message, messageLength);
}