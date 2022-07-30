// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "TrustedComponent.h"

const unsigned char* GetAgentDerCertificate(size_t *pCertLen);

extern TrustedComponent* g_RequestedComponentList;

extern "C" {
    int ecall_ProcessError(void* sessionHandle);

    int ecall_RequestPolicyCheck(void);
}
