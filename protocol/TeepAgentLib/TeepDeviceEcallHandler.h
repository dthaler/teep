// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "TrustedComponent.h"

extern TrustedComponent* g_RequestedComponentList;

extern "C" {
    int ecall_ProcessError(void* sessionHandle);

    int ecall_RequestPolicyCheck(void);
}
