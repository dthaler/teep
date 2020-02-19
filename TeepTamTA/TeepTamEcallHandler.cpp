/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include "TeepTam_t.h"

#include <stdbool.h>
#include <string.h>
extern "C" {
#include "jansson.h"
#include "joseinit.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
#include "jose/jws.h"
#include "jose/b64.h"
#include "jose/openssl.h"
#include "../TeepCommonTALib/common.h"
};
#include "../jansson/JsonAuto.h"
#include "openssl/x509.h"
#include "openssl/evp.h"
#include "OTrPTamEcallHandler.h"
#include "TeepTamEcallHandler.h"

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

const unsigned char* g_TamDerCertificate = nullptr;
size_t g_TamDerCertificateSize = 0;

const unsigned char* GetTamDerCertificate(size_t *pCertLen)
{
    if (g_TamDerCertificate == nullptr) {
        // Construct a self-signed DER certificate based on the JWK.

        // First get the RSA key.
        json_t* jwk = GetTamEncryptionKey();
        g_TamDerCertificate = GetDerCertificate(jwk, &g_TamDerCertificateSize);
    }

    *pCertLen = g_TamDerCertificateSize;
    return g_TamDerCertificate;
}

json_t* GetNewGloballyUniqueID(void);

/* Construct a unique request token.  The TEEP spec does not say what
 * the scope of uniqueness needs to be, but we currently try to use
 * globally unique value.
 */
json_t* GetNewToken(void)
{
    return GetNewGloballyUniqueID();
}

/* Compose a Query Request message to be signed. */
const char* TeepComposeQueryRequestTBS(void)
{
    JsonAuto request(json_object(), true);
    if (request == nullptr) {
        return nullptr;
    }
    if (request.AddIntegerToObject("TYPE", TEEP_QUERY_REQUEST) == nullptr) {
        return nullptr;
    }

    if (request.AddObjectToObject("TOKEN", GetNewToken()) == nullptr) {
        return nullptr;
    }

    JsonAuto dataItems = request.AddArrayToObject("REQUEST");
    if (dataItems == nullptr) {
        return nullptr;
    }
    if (dataItems.AddIntegerToArray(TEEP_TRUSTED_APPS) == nullptr) {
        return nullptr;
    }

    /* Convert to message buffer. */
    const char* message = json_dumps(request, 0);
    return message;
}

const char* TeepComposeQueryRequest(void)
{
    /* Compose a raw QueryRequest message to be signed. */
    const char* tbsRequest = TeepComposeQueryRequestTBS();
    if (tbsRequest == nullptr) {
        return nullptr;
    }
#ifdef _DEBUG
    printf("Sending TBS: %s\n", tbsRequest);
#endif

    return tbsRequest;
}

/* Handle a new incoming connection from a device. */
int TeepProcessConnect(void* sessionHandle)
{
    printf("Received client connection\n");

    const char* message = TeepComposeQueryRequest();
    if (message == nullptr) {
        return 1; /* Error */
    }

    printf("Sending QueryRequest...\n");

    int err = 0;
    oe_result_t result = ocall_QueueOutboundTeepMessage(&err, sessionHandle, TEEP_JSON_MEDIA_TYPE, message);
    free((void*)message);
    if (result != OE_OK) {
        return result;
    }

    return err;
}

int ecall_ProcessTeepConnect(void* sessionHandle, const char* acceptMediaType)
{
    if (strncmp(acceptMediaType, OTRP_JSON_MEDIA_TYPE, strlen(OTRP_JSON_MEDIA_TYPE)) == 0) {
        return OTrPProcessConnect(sessionHandle);
    } else if (strncmp(acceptMediaType, TEEP_JSON_MEDIA_TYPE, strlen(TEEP_JSON_MEDIA_TYPE)) == 0) {
        return TeepProcessConnect(sessionHandle);
    } else {
        return 1;
    }
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

/* Handle an incoming message from a TEEP Agent. */
/* Returns 0 on success, or non-zero if error. */
int TeepHandleJsonMessage(void* sessionHandle, const char* message, unsigned int messageLength)
{
    /* Unrecognized message. */
    return 1;
}
