/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    int TeepHandleConnect(void);

    int TeepHandleMessage(void* sessionHandle, const char* mediaType, const char* message, int messageLength);
    int OTrPHandleMessage(void* sessionHandle, const char* mediaType, const char* message, int messageLength);

    int StartAgentBroker(void);
    void StopAgentBroker(void);

    int AgentBrokerRequestTA(
        const char* taid,
        const char* tamUri);

#ifdef __cplusplus
};
#endif
