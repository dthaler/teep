/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

typedef struct {
    char TamUri[1024];
    char OutboundMediaType[80];
    const char* OutboundMessage;
    char InboundMediaType[80];
    const char* InboundMessage;
} TeepSession;

extern TeepSession g_Session;