/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    int TeepHandleMessage(
        _In_ void* sessionHandle,
        _In_z_ const char* mediaType,
        _In_reads_(messageLength) const char *message,
        _In_ int messageLength);

    int TeepHandleConnect(_In_ void* sessionHandle, _In_z_ const char* acceptMediaType);

    int StartTamBroker(void);
    void StopTamBroker(void);

    int TamBrokerProcess(void);

#ifdef __cplusplus
};
#endif
