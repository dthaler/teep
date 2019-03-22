/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

typedef struct {
    char TamUri[1024];
    const char* MessageToSend;
    const char* ResponseBuffer;
} OTrPSession;

extern OTrPSession g_Session;