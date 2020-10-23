/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    int TeepHandleConnect(void);

    int TeepHandleMessage(_In_ void* sessionHandle, _In_z_ const char* mediaType, _In_reads_(messageLength) const char* message, int messageLength);
    int OTrPHandleMessage(_In_ void* sessionHandle, _In_z_ const char* mediaType, _In_reads_(messageLength) const char* message, int messageLength);

    int StartAgentBroker(void);
    void StopAgentBroker(void);

    int AgentBrokerRequestTA(
        int useCbor,
        oe_uuid_t taid,
        _In_z_ const char* tamUri);

#ifdef __cplusplus
};
#endif
