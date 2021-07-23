// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    const char* SendTeepMessage(TeepSession* session, char** pResponseMediaType, int* pResponseLength);

#ifdef __cplusplus
};
#endif
