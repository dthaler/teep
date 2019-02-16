/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    int OTrPHandleMessage(
        _In_reads_(messageLength) const char *message,
        _In_ int messageLength);

    int OTrPHandleConnect(void);

    int StartTamBroker(void);
    void StopTamBroker(void);

#ifdef __cplusplus
};
#endif
