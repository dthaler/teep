// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#define sprintf_s(dest, len, ...) sprintf(dest, __VA_ARGS__)
#endif
#include <stdio.h>
#include <string.h>
#include "TrustedComponent.h"

TrustedComponent::TrustedComponent(teep_uuid_t id)
{
    this->ID = id;
}

TrustedComponent::~TrustedComponent()
{
}

// Returns TRUE on success, FALSE on failure.
int TrustedComponent::ConvertUUIDToString(char* buffer, size_t buffer_length, teep_uuid_t uuid)
{
    if (buffer_length < 37) {
        // Failure.
        memset(buffer, 0, buffer_length);
        return 0;
    }
    sprintf_s(buffer, buffer_length,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid.b[0], uuid.b[1], uuid.b[2], uuid.b[3], uuid.b[4], uuid.b[5], uuid.b[6], uuid.b[7],
        uuid.b[8], uuid.b[9], uuid.b[10], uuid.b[11], uuid.b[12], uuid.b[13], uuid.b[14], uuid.b[15]);
    return 1;
}
