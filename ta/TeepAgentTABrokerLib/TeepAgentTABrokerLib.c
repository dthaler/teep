// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include <openenclave/host.h>
#include "TeepAgentBrokerLib.h"
#include "TeepSession.h"

// TODO: investigate why it links with this line
// but has undefined symbols without it.
#define ecall_TeepAgentRequestTA TeepAgent_ecall_TeepAgentRequestTA
#include "TeepAgent_u.h"

#define ASSERT(x) if (!(x)) { DebugBreak(); }

oe_enclave_t* g_ta_eid = NULL;

teep_error_code_t TeepAgentRequestTA(
    teep_uuid_t requestedTaid,
    _In_z_ const char* tamUri)
{
    teep_error_code_t err;
    oe_uuid_t oeTaid = *(oe_uuid_t*)&requestedTaid;
    oe_result_t result = ecall_TeepAgentRequestTA(g_ta_eid, (int*)&err, oeTaid, tamUri);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

teep_error_code_t TeepAgentUnrequestTA(
    teep_uuid_t unneededTaid,
    _In_z_ const char* tamUri)
{
    teep_error_code_t err;
    oe_uuid_t oeTaid = *(oe_uuid_t*)&unneededTaid;
    oe_result_t result = ecall_TeepAgentUnrequestTA(g_ta_eid, (int*)&err, oeTaid, tamUri);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

teep_error_code_t TeepAgentProcessTeepMessage(
    _In_ void* sessionHandle,
    _In_z_ const char* mediaType,
    _In_reads_(messageLength) const char* message,
    size_t messageLength)
{
    teep_error_code_t err;
    oe_result_t result = ecall_TeepAgentProcessTeepMessage(
        g_ta_eid,
        (int*)&err,
        sessionHandle,
        mediaType,
        message,
        messageLength);
    if (result != OE_OK) {
        return TEEP_ERR_PERMANENT_ERROR;
    }
    return err;
}

teep_error_code_t TeepAgentLoadConfiguration(_In_z_ const char* dataDirectory)
{
    teep_error_code_t err;
    oe_result_t result = ecall_TeepAgentLoadConfiguration(g_ta_eid, (int*)&err, dataDirectory);
    if (result != OE_OK) {
        return TEEP_ERR_PERMANENT_ERROR;
    }
    return err;
}

teep_error_code_t TeepAgentInitializeKeys(_In_z_ const char* dataDirectory, _Out_writes_opt_z_(256) char* publicKeyFilename)
{
    teep_error_code_t err;
    oe_result_t result = ecall_TeepAgentInitializeKeys(g_ta_eid, (int*)&err, dataDirectory, publicKeyFilename);
    if (result != OE_OK) {
        return TEEP_ERR_PERMANENT_ERROR;
    }
    return err;
}

int TeepInitialize(void)
{
    return ecall_TeepInitialize(g_ta_eid);
}

int ocall_TeepAgentConnect(const char* tamUri, const char* acceptMediaType)
{
    return TeepAgentConnect(tamUri, acceptMediaType);
}

int ocall_TeepAgentQueueOutboundTeepMessage(void* sessionHandle, const char* mediaType, const char* message, size_t messageLength)
{
    return TeepAgentQueueOutboundTeepMessage(sessionHandle, mediaType, message, messageLength);
}
