// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "TeepCommonTALib_t.h"
#include "common.h"

void ecall_Initialize(void)
{
    TeepInitialize();
}

int ecall_ProcessTeepMessage(
    void* sessionHandle,
    const char* mediaType,
    const char* message,
    size_t messageLength)
{
    return ProcessTeepMessage(
        sessionHandle,
        mediaType,
        message,
        messageLength);
}