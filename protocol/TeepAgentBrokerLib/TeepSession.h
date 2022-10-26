// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>

typedef struct {
    char OutboundMediaType[80];
    const char* OutboundMessage;
    size_t OutboundMessageLength;
    uint64_t OutboundMessagesSent; // Counter used for diagnostic purposes.
} TeepBasicSession;

typedef struct {
    TeepBasicSession Basic;
    char TamUri[1024];
    char InboundMediaType[80];
    const char* InboundMessage;
    size_t InboundMessageLength;
} TeepAgentSession;

#ifdef __cplusplus
extern "C" {
#endif

    extern TeepAgentSession g_Session;

#ifdef __cplusplus
};
#endif
