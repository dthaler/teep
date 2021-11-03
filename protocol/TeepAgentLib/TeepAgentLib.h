// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

    // Calls down to broker.
    int Connect(
        const char* tamUri,
        const char* acceptMediaType);
    teep_error_code_t TeepAgentQueueOutboundTeepMessage(
        _In_ void* sessionHandle,
        _In_z_ const char* mediaType,
        _In_reads_(messageLength) const char* message,
        size_t messageLength);

    // Calls up from broker.
    int TeepAgentProcessTeepMessage(
        _In_ void* sessionHandle,
        _In_z_ const char* mediaType,
        _In_reads_(messageLength) const char* message,
        size_t messageLength);
    int TeepHandleConnect(void);

    int RequestTA(
        int useCbor,
        teep_uuid_t requestedTaid,
        const char* tamUri);

    int UnrequestTA(
        int useCbor,
        teep_uuid_t unneededTaid,
        const char* tamUri);
    
    int OTrPHandleMessage(_In_ void* sessionHandle, _In_z_ const char* mediaType, _In_reads_(messageLength) const char* message, int messageLength);

    // TODO: move these out of this file.
    int StartAgentBroker(int simulated_tee);
    void StopAgentBroker(void);

#ifdef __cplusplus
};
#endif
