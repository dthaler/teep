// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <openenclave/host.h>
#include "TeepTamBrokerLib.h"

// TODO: investigate why it links with this line
// but has undefined symbols without it.
#define ecall_Initialize TeepTam_ecall_Initialize
#include "TeepTam_u.h"

oe_enclave_t* g_ta_eid = NULL;

// Forward an incoming TEEP message, which might be from any session.
int ProcessTeepMessage(
    _In_ void* sessionHandle,
    _In_z_ const char* mediaType,
    _In_reads_(messageLength) const char* message,
    size_t messageLength)
{
    int err = 0;
    oe_result_t result = ecall_ProcessTeepMessage(g_ta_eid, &err, sessionHandle, mediaType, message, messageLength);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

int TamProcessConnect(_In_ void* sessionHandle, _In_z_ const char* acceptMediaType)
{
    int err = 0;
    oe_result_t result = ecall_ProcessTeepConnect(g_ta_eid, &err, sessionHandle, acceptMediaType);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

int TeepInitialize(void)
{
    return ecall_Initialize(g_ta_eid);
}

int ocall_QueueOutboundTeepMessage(void* sessionHandle, const char* mediaType, const char* message, size_t messageLength)
{
    return QueueOutboundTeepMessage(sessionHandle, mediaType, message, messageLength);
}