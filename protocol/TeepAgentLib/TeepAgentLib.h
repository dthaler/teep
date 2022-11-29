// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

    // Calls down to broker.
    teep_error_code_t TeepAgentConnect(
        _In_z_ const char* tamUri,
        _In_z_ const char* acceptMediaType);
    teep_error_code_t TeepAgentQueueOutboundTeepMessage(
        _In_ void* sessionHandle,
        _In_z_ const char* mediaType,
        _In_reads_(messageLength) const char* message,
        size_t messageLength);

    // Calls up from broker.
    teep_error_code_t TeepAgentLoadConfiguration(_In_z_ const char* dataDirectory);
    teep_error_code_t TeepAgentInitializeKeys(
        _In_z_ const char* dataDirectory,
        teep_signature_kind_t signatureKind,
        _Out_writes_opt_z_(256) char* publicKeyFilename);

    teep_error_code_t TeepAgentProcessTeepMessage(
        _In_ void* sessionHandle,
        _In_z_ const char* mediaType,
        _In_reads_(messageLength) const char* message,
        size_t messageLength);

    teep_error_code_t TeepAgentRequestTA(
        teep_uuid_t requestedTaid,
        _In_z_ const char* tamUri);

    teep_error_code_t TeepAgentUnrequestTA(
        teep_uuid_t unneededTaid,
        _In_z_ const char* tamUri);

    teep_error_code_t TeepAgentProcessError(_In_ void* sessionHandle);
    teep_error_code_t TeepAgentRequestPolicyCheck(_In_z_ const char* tamUri);
    void TeepAgentShutdown();

#ifdef __cplusplus
};
#endif
