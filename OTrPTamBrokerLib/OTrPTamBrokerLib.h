/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    int OTrPHandleMessage(
        _In_ void* sessionHandle,
        _In_reads_(messageLength) const char *message,
        _In_ int messageLength);

    int OTrPHandleConnect(_In_ void* sessionHandle);

    int StartTamBroker(void);
    void StopTamBroker(void);

    int TamBrokerProcess(void);

#ifdef __cplusplus
};
#endif
