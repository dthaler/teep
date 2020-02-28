/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include "TeepAgent_t.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "TrustedApplication.h"
extern "C" {
#include "jansson.h"
#include "joseinit.h"
#include "jose/b64.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
#include "jose/jws.h"
#include "jose/openssl.h"
#include "../TeepCommonTALib/common.h"
};
#include "../jansson/JsonAuto.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "TeepDeviceEcallHandler.h"

// List of TA's requested.
TrustedApplication* g_TARequestList = nullptr;

const unsigned char* g_AgentDerCertificate = nullptr;
size_t g_AgentDerCertificateSize = 0;

const unsigned char* GetAgentDerCertificate(size_t* pCertLen)
{
    if (g_AgentDerCertificate == nullptr) {
        // Construct a self-signed DER certificate based on the JWK.

        // First get the RSA key.
        json_t* jwk = GetAgentSigningKey();
        g_AgentDerCertificate = GetDerCertificate(jwk, &g_AgentDerCertificateSize);
    }

    *pCertLen = g_AgentDerCertificateSize;
    return g_AgentDerCertificate;
}

int ecall_ProcessError(void* sessionHandle)
{
    (void)sessionHandle;
    // TODO: process transport error
    return 0;
}

int ecall_RequestPolicyCheck(void)
{
    // TODO: request policy check
    return 0;
}

/* Compose a TEEP QueryResponse message. */
const char* TeepComposeQueryResponse(
    const json_t* request)    // Request we're responding to.
{
    JsonAuto response(json_object(), true);
    if (response == nullptr) {
        return nullptr;
    }
    if (response.AddIntegerToObject("TYPE", TEEP_QUERY_RESPONSE) == nullptr) {
        return nullptr;
    }

    /* Copy TOKEN from request. */
    json_t* token = json_object_get(request, "TOKEN");
    if (!json_is_string(token) || (json_string_value(token) == nullptr)) {
        return nullptr;
    }
    if (response.AddStringToObject("TOKEN", json_string_value(token)) == nullptr) {
        return nullptr;
    }

    JsonAuto requestedtalist = response.AddArrayToObject("REQUESTED_TA_LIST");
    if (requestedtalist == nullptr) {
        return nullptr;
    }
    for (TrustedApplication* ta = g_TARequestList; ta != nullptr; ta = ta->Next) {
        if (requestedtalist.AddStringToArray(ta->ID) == nullptr) {
            return nullptr;
        }
    }

    /* Convert to message buffer. */
    const char* message = json_dumps(response, 0);
    return message;
}

// Returns 0 on success, non-zero on error.
int TeepHandleQueryRequest(void* sessionHandle, json_t* object)
{
    int err = 1;
    oe_result_t result;

    printf("TeepHandleQueryRequest\n");
    if (!json_is_object(object)) {
        return 1; /* Error */
    }

    /* 1.  Validate JSON message signing.  If it doesn't pass, an error message is returned. */
    /* ... */

    /* 2.  Validate that the request TAM certificate is chained to a trusted
     *     CA that the TEE embeds as its trust anchor.
     *
     *     *  Cache the CA OCSP stapling data and certificate revocation
     *        check status for other subsequent requests.
     *
     *     *  A TEE can use its own clock time for the OCSP stapling data
     *        validation.
     */
    /* ...*/

    /* 3. Compose a response. */
    const char* message = TeepComposeQueryResponse(object);

    printf("Sending QueryResponse: %s\n\n", message);

    result = ocall_QueueOutboundTeepMessage(&err, sessionHandle, TEEP_JSON_MEDIA_TYPE, message);
    free((void*)message);
    if (result != OE_OK) {
        return result;
    }
    return 0;
}

/* Compose a TEEP Success message. */
const char* TeepComposeSuccess(
    const json_t* request)    // Request we're responding to.
{
    JsonAuto response(json_object(), true);
    if (response == nullptr) {
        return nullptr;
    }
    if (response.AddIntegerToObject("TYPE", TEEP_SUCCESS) == nullptr) {
        return nullptr;
    }

    /* Copy TOKEN from request. */
    json_t* token = json_object_get(request, "TOKEN");
    if (!json_is_string(token) || (json_string_value(token) == nullptr)) {
        return nullptr;
    }
    if (response.AddStringToObject("TOKEN", json_string_value(token)) == nullptr) {
        return nullptr;
    }

    /* Convert to message buffer. */
    const char* message = json_dumps(response, 0);
    return message;
}

/* Compose a TEEP Error message. */
const char* TeepComposeError(
    const json_t* request,    // Request we're responding to.
    int errorCode)
{
    JsonAuto response(json_object(), true);
    if (response == nullptr) {
        return nullptr;
    }
    if (response.AddIntegerToObject("TYPE", TEEP_ERROR) == nullptr) {
        return nullptr;
    }

    /* Copy TOKEN from request. */
    json_t* token = json_object_get(request, "TOKEN");
    if (!json_is_string(token) || (json_string_value(token) == nullptr)) {
        return nullptr;
    }
    if (response.AddStringToObject("TOKEN", json_string_value(token)) == nullptr) {
        return nullptr;
    }

    if (response.AddIntegerToObject("ERR_CODE", errorCode) == nullptr) {
        return nullptr;
    }

    /* Convert to message buffer. */
    const char* message = json_dumps(response, 0);
    return message;
}

// Returns 0 on success, non-zero on error.
int TeepHandleTrustedAppInstall(void* sessionHandle, json_t* request)
{
    printf("TeepHandleTrustedAppInstall\n");

    if (!json_is_object(request)) {
        return 1; /* Error */
    }

    int err = 1;
    oe_result_t result;

    /* 1.  Validate JSON message signing.  If it doesn't pass, an error message is returned. */
    /* ... */

    /* 2.  Validate that the request TAM certificate is chained to a trusted
     *     CA that the TEE embeds as its trust anchor.
     *
     *     *  Cache the CA OCSP stapling data and certificate revocation
     *        check status for other subsequent requests.
     *
     *     *  A TEE can use its own clock time for the OCSP stapling data
     *        validation.
     */
    /* ... */

#if 0
    const char* message = TeepComposeSuccess(request);
    printf("Sending Success: %s\n\n", message);
#else
    const char* message = TeepComposeError(request, ERR_INTERNAL_ERROR);
    printf("Sending Error: %s\n\n", message);
#endif

    result = ocall_QueueOutboundTeepMessage(&err, sessionHandle, OTRP_JSON_MEDIA_TYPE, message);
    free((void*)message);
    if (result != OE_OK) {
        return result;
    }
    return 0;
}

int TeepHandleTrustedAppDelete(void* sessionHandle, json_t* object)
{
    (void)sessionHandle; // Unused.
    (void)object; // Unused.

    printf("TeepHandleTrustedAppDelete\n");
    return 1;
}

int TeepHandleRawJsonMessage(void* sessionHandle, json_t* object)
{
    // Get message TYPE value.
    JsonAuto typeValue = json_object_get(object, "TYPE");
    if (!json_is_integer((json_t*)typeValue)) {
        return 1;
    }
    teep_message_type_t messageType = (teep_message_type_t)json_integer_value(typeValue);

    printf("TYPE=%d\n", messageType);

    switch (messageType) {
    case TEEP_QUERY_REQUEST:
        return TeepHandleQueryRequest(sessionHandle, object);
    case TEEP_TRUSTED_APP_INSTALL:
        return TeepHandleTrustedAppInstall(sessionHandle, object);
    case TEEP_TRUSTED_APP_DELETE:
        return TeepHandleTrustedAppDelete(sessionHandle, object);
    default:
        // Not a legal message from the TAM.
        return 1;
    }
}

// Returns 0 on success, non-zero on error.
int TeepHandleJsonMessage(void* sessionHandle, const char* message, unsigned int messageLength)
{
    char* newstr = nullptr;

    /* Verify message is null-terminated. */
    const char* str = message;
    if (message[messageLength - 1] == 0) {
        str = message;
    } else {
        newstr = (char*)malloc(messageLength + 1);
        if (newstr == nullptr) {
            return 1; /* error */
        }
        memcpy(newstr, message, messageLength);
        newstr[messageLength] = 0;
        str = newstr;
    }

    printf("Received message='%s'\n", str);

    json_error_t error;
    JsonAuto object(json_loads(str, 0, &error), true);

    free(newstr);
    newstr = nullptr;

    if ((object == nullptr) || !json_is_object((json_t*)object)) {
        return 1; /* Error */
    }

    /* 1.  Validate JSON message signing.  If it doesn't pass, an error message is returned. */
    char* payload = DecodeJWS(object, nullptr);
    if (!payload) {
        // For now, we continue and just use plain JSON.
        // Later, we should return an error.
        // return 1; /* Error */
        return TeepHandleRawJsonMessage(sessionHandle, (json_t*)object);
    } else {
        json_error_t error;
        JsonAuto request(json_loads(payload, 0, &error), true);
        if ((json_t*)request == nullptr) {
            return 1;
        }
        return TeepHandleRawJsonMessage(sessionHandle, (json_t*)request);
    }
}

int ecall_RequestTA(
    const char* taid,
    const char* tamUri)
{
    printf("ecall_RequestTA\n");
    int err = 0;
    oe_result_t result = OE_OK;

    // TODO: See whether taid is already installed.
    // For now we skip this step and pretend it's not.
    bool isInstalled = false;

    if (isInstalled) {
        // Already installed, nothing to do.
        // This counts as "pass no data back" in the broker spec.
        return 0;
    }

    // See whether taid is already requested.
    TrustedApplication* ta;
    for (ta = g_TARequestList; ta != nullptr; ta = ta->Next) {
        if (strcmp(ta->ID, taid) == 0) {
            // Already requested, nothing to do.
            // This counts as "pass no data back" in the broker spec.
            return 0;
        }
    }

    // Add taid to the request list.
    ta = new TrustedApplication(taid);
    ta->Next = g_TARequestList;
    g_TARequestList = ta;

    // TODO: we may want to modify the TAM URI here.

    // TODO: see whether we already have a TAM cert we trust.
    // For now we skip this step and say we don't.
    bool haveTrustedTamCert = false;

    if (!haveTrustedTamCert) {
        // Pass back a TAM URI with no buffer.
        result = ocall_Connect(&err, tamUri, TEEP_JSON_MEDIA_TYPE); // TODO: configure media type
        if (result != OE_OK) {
            return result;
        }
        if (err != 0) {
            return err;
        }
    } else {
        // TODO: implement going on to the next message.
        oe_assert(false);
    }

    return err;
}

JsonAuto g_AgentSigningKey;

json_t* GetAgentSigningKey()
{
    if ((json_t*)g_AgentSigningKey == nullptr) {
        g_AgentSigningKey = CreateNewJwkRS256();
    }
    return (json_t*)g_AgentSigningKey;
}

JsonAuto g_AgentEncryptionKey;

json_t* GetAgentEncryptionKey()
{
    if ((json_t*)g_AgentEncryptionKey == nullptr) {
        g_AgentEncryptionKey = CopyToJweKey(GetAgentSigningKey(), "RSA1_5");
    }
    return g_AgentEncryptionKey;
}