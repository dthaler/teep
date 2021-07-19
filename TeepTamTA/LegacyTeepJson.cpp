// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/* This file is now obsolete.  It will be deleted once we add COSE support. */

#if defined(TEEP_ENABLE_JSON) || defined(ENABLE_OTRP)
#include <openenclave/enclave.h>
#include "TeepTam_t.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "jansson.h"
#include "joseinit.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
#include "jose/jws.h"
#include "jose/b64.h"
#include "jose/openssl.h"
};
#include "../jansson/JsonAuto.h"
#include "OTrPTamEcallHandler.h"

json_t* GetNewGloballyUniqueID(void);

/* Construct a unique request token.  The TEEP spec does not say what
 * the scope of uniqueness needs to be, but we currently try to use
 * globally unique value.
 */
json_t* GetNewToken(void)
{
    return GetNewGloballyUniqueID();
}
#endif

#ifdef TEEP_ENABLE_JSON

JsonAuto g_TamSigningKey;

json_t* GetTamSigningKey()
{
    if ((json_t*)g_TamSigningKey == nullptr) {
        g_TamSigningKey = CreateNewJwkRS256();
    }
    return (json_t*)g_TamSigningKey;
}

JsonAuto g_TamEncryptionKey;

json_t* GetTamEncryptionKey()
{
    if ((json_t*)g_TamEncryptionKey == nullptr) {
        g_TamEncryptionKey = CopyToJweKey(GetTamSigningKey(), "RSA1_5");
    }
    return g_TamEncryptionKey;
}

// Compose a JSON Query Request message to be signed.
const char* TeepComposeJsonQueryRequestTBS(void)
{
    JsonAuto request(json_object(), true);
    if (request == nullptr) {
        return nullptr;
    }
    if (request.AddIntegerToObject("TYPE", TEEP_MESSAGE_QUERY_REQUEST) == nullptr) {
        return nullptr;
    }

    if (request.AddObjectToObject("TOKEN", GetNewToken()) == nullptr) {
        return nullptr;
    }

    JsonAuto dataItems = request.AddArrayToObject("REQUEST");
    if (dataItems == nullptr) {
        return nullptr;
    }
    if (dataItems.AddIntegerToArray(TEEP_TRUSTED_COMPONENTS) == nullptr) {
        return nullptr;
    }

    // Convert to message buffer.
    const char* message = json_dumps(request, 0);
    return message;
}

const char* TeepComposeJsonQueryRequest()
{
    // Compose a raw QueryRequest message to be signed.
    const char* tbsRequest = TeepComposeJsonQueryRequestTBS();
    if (tbsRequest == nullptr) {
        return nullptr;
    }
#ifdef _DEBUG
    printf("Sending TBS: %s\n", tbsRequest);
#endif
    return tbsRequest;
}

// Get the BASE64-encoded SHA256 hash value of the buffer.
json_t* GetSha256Hash(void* buffer, int len)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buffer, len);
    SHA256_Final(hash, &sha256);

    return jose_b64_enc(hash, sizeof(hash));
}

#endif // TEEP_ENABLE_JSON
