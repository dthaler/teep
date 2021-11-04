// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include "TeepSession.h"

#ifdef __cplusplus
extern "C" {
#endif

    const char* SendTeepMessage(TeepAgentSession* session, char** pResponseMediaType, int* pResponseLength);

#ifdef __cplusplus
};
#endif
