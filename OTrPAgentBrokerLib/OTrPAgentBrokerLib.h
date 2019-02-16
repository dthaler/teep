/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    int OTrPHandleConnect(void);

    int OTrPHandleMessage(const char *message, int messageLength);

    int StartAgentBroker(void);
    void StopAgentBroker(void);

#ifdef __cplusplus
};
#endif
