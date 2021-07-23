// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <openenclave/host.h>
#include "TeepAgentBrokerLib.h"
#include "TeepSession.h"

// TODO: investigate why it links with this line
// but has undefined symbols without it.
#define ecall_RequestTA TeepAgent_ecall_RequestTA
#include "TeepAgent_u.h"

#define ASSERT(x) if (!(x)) { DebugBreak(); }

oe_enclave_t* g_ta_eid = NULL;

int RequestTA(
    int useCbor,
    teep_uuid_t requestedTaid,
    _In_z_ const char* tamUri)
{
    int err;
    oe_uuid_t oeTaid = *(oe_uuid_t*)&requestedTaid;
    oe_result_t result = ecall_RequestTA(g_ta_eid, &err, useCbor, oeTaid, tamUri);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

int UnrequestTA(
    int useCbor,
    teep_uuid_t unneededTaid,
    _In_z_ const char* tamUri)
{
    int err;
    oe_uuid_t oeTaid = *(oe_uuid_t*)&unneededTaid;
    oe_result_t result = ecall_UnrequestTA(g_ta_eid, &err, useCbor, oeTaid, tamUri);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

int ProcessTeepMessage(
    TeepSession* session,
    const char* inboundMediaType,
    const char* inboundMessage,
    size_t inboundMessageLength)
{
    int err;
    oe_result_t result = ecall_ProcessTeepMessage(
        g_ta_eid,
        &err,
        session,
        inboundMediaType,
        inboundMessage,
        inboundMessageLength);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

int TeepInitialize(void)
{
    return ecall_Initialize(g_ta_eid);
}

int ocall_Connect(const char* tamUri, const char* acceptMediaType)
{
    return Connect(tamUri, acceptMediaType);
}

int ocall_QueueOutboundTeepMessage(void* sessionHandle, const char* mediaType, const char* message, size_t messageLength)
{
    return QueueOutboundTeepMessage(sessionHandle, mediaType, message, messageLength);
}
