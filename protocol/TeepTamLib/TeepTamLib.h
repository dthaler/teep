// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

    int ProcessConnect(_In_ void* sessionHandle, _In_z_ const char* acceptMediaType);

    // TODO: move these out of this file.
    int StartTamBroker(_In_z_ const char* manifestDirectory, int simulated_tee);
    void StopTamBroker(void);

#ifdef __cplusplus
};
#endif
