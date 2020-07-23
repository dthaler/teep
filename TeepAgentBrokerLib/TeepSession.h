/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

typedef struct {
    char TamUri[1024];
    char OutboundMediaType[80];
    const char* OutboundMessage;
    int OutboundMessageLength;
    char InboundMediaType[80];
    const char* InboundMessage;
    int InboundMessageLength;
} TeepSession;

extern TeepSession g_Session;