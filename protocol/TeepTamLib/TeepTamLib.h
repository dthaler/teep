// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

    teep_error_code_t TamLoadConfiguration(_In_z_ const char* dataDirectory);
    teep_error_code_t TamInitializeKeys(_In_z_ const char* dataDirectory, _Out_writes_opt_z_(256) char* publicKeyFilename);

    teep_error_code_t TamProcessTeepMessage(
        _In_ void* sessionHandle,
        _In_z_ const char* mediaType,
        _In_reads_(messageLength) const char* message,
        size_t messageLength);
    teep_error_code_t TamProcessConnect(_In_ void* sessionHandle, _In_z_ const char* acceptMediaType);

    teep_error_code_t TamQueueOutboundTeepMessage(
        _In_ void* sessionHandle,
        _In_z_ const char* mediaType,
        _In_reads_(messageLength) const char* message,
        size_t messageLength);

#ifdef __cplusplus
};
#endif
