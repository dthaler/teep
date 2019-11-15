/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

typedef struct {
    char TamUri[1024];
    const char* OutboundMessage;
    const char* InboundMessage;
} TeepSession;

extern TeepSession g_Session;