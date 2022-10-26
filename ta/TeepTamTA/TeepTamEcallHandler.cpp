// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include "Manifest.h"
#include "TeepTamLib.h"
#include "TeepTam_t.h"

int ecall_ProcessTeepConnect(void* sessionHandle, const char* acceptMediaType)
{
    return ProcessConnect(sessionHandle, acceptMediaType);
}