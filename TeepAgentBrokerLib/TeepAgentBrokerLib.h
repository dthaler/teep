// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#ifdef TEEP_USE_TEE
typedef oe_uuid_t teep_uuid_t;
#define TEEP_UUID_SIZE OE_UUID_SIZE
#else
#include <rpc.h>
typedef uuid_t teep_uuid_t;
#define TEEP_UUID_SIZE sizeof(teep_uuid_t)
#endif

#ifdef __cplusplus
extern "C" {
#endif

    int TeepHandleConnect(void);

    int TeepHandleMessage(_In_ void* sessionHandle, _In_z_ const char* mediaType, _In_reads_(messageLength) const char* message, int messageLength);
    int OTrPHandleMessage(_In_ void* sessionHandle, _In_z_ const char* mediaType, _In_reads_(messageLength) const char* message, int messageLength);

    int StartAgentBroker(int simulated_tee);
    void StopAgentBroker(void);

    int AgentBrokerRequestTA(
        int useCbor,
        teep_uuid_t unneededTaid,
        _In_z_ const char* tamUri);

    int AgentBrokerUnrequestTA(
        int useCbor,
        teep_uuid_t unneededTaid,
        _In_z_ const char* tamUri);

#ifdef __cplusplus
};
#endif
