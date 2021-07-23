// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

typedef struct {
    char TamUri[1024];
    char OutboundMediaType[80];
    const char* OutboundMessage;
    size_t OutboundMessageLength;
    char InboundMediaType[80];
    const char* InboundMessage;
    size_t InboundMessageLength;
} TeepSession;

extern TeepSession g_Session;
