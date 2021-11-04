// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

    // Calls down to broker.
    teep_error_code_t TeepAgentConnect(
        _In_z_ const char* tamUri,
        _In_z_ const char* acceptMediaType);
    teep_error_code_t TeepAgentQueueOutboundTeepMessage(
        _In_ void* sessionHandle,
        _In_z_ const char* mediaType,
        _In_reads_(messageLength) const char* message,
        size_t messageLength);

    // Calls up from broker.
    teep_error_code_t TeepAgentProcessTeepMessage(
        _In_ void* sessionHandle,
        _In_z_ const char* mediaType,
        _In_reads_(messageLength) const char* message,
        size_t messageLength);

    int TeepAgentRequestTA(
        int useCbor,
        teep_uuid_t requestedTaid,
        _In_z_ const char* tamUri);

    int TeepAgentUnrequestTA(
        int useCbor,
        teep_uuid_t unneededTaid,
        _In_z_ const char* tamUri);

    teep_error_code_t TeepAgentProcessError(void* sessionHandle);
    teep_error_code_t TeepAgentRequestPolicyCheck(_In_z_ const char* tamUri);
    
    int OTrPHandleMessage(_In_ void* sessionHandle, _In_z_ const char* mediaType, _In_reads_(messageLength) const char* message, int messageLength);

    // TODO: move these out of this file.
    int StartAgentBroker(int simulated_tee);
    void StopAgentBroker(void);

#ifdef __cplusplus
};
#endif
