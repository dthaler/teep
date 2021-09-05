// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <string.h>
#include <string>
#include "TrustedComponent.h"
extern "C" {
#ifdef TEEP_ENABLE_JSON
#include "jansson.h"
#include "joseinit.h"
#include "jose/b64.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
#include "jose/jws.h"
#include "jose/openssl.h"
#endif
};
#include "otrp.h"
#include "teep_protocol.h"
#include "TeepAgentLib.h"
#ifdef TEEP_ENABLE_JSON
#include "../jansson/JsonAuto.h"
#endif
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"
#include "TeepDeviceEcallHandler.h"
#include "SuitParser.h"
#include <sstream>

// List of requested Trusted Components.
TrustedComponent* g_RequestedComponentList = nullptr;

// List of unneeded Trusted Components.
TrustedComponent* g_UnneededComponentList = nullptr;

const unsigned char* g_AgentDerCertificate = nullptr;
size_t g_AgentDerCertificateSize = 0;

const unsigned char* GetAgentDerCertificate(size_t* pCertLen)
{
    if (g_AgentDerCertificate == nullptr) {
        // Construct a self-signed DER certificate based on the JWK.

        // First get the RSA key.
#ifdef TEEP_ENABLE_JSON
        json_t* jwk = GetAgentSigningKey();
        g_AgentDerCertificate = GetDerCertificate(jwk, &g_AgentDerCertificateSize);
#else
        // TODO
        return nullptr;
#endif
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

#ifdef TEEP_ENABLE_JSON
/* Compose a TEEP QueryResponse message. */
const char* TeepComposeJsonQueryResponse(
    const json_t* request)    // Request we're responding to.
{
    JsonAuto response(json_object(), true);
    if (response == nullptr) {
        return nullptr;
    }
    if (response.AddIntegerToObject("TYPE", TEEP_MESSAGE_QUERY_RESPONSE) == nullptr) {
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

    if (g_RequestedComponentList != nullptr) {
        JsonAuto requested_component_list = response.AddArrayToObject("REQUESTED_TC_LIST");
        if (requested_component_list == nullptr) {
            return nullptr;
        }
        char IDString[37];
        for (TrustedComponent* component = g_RequestedComponentList; component != nullptr; component = component->Next) {
            TrustedComponent::ConvertUUIDToString(IDString, sizeof(IDString), component->ID);
            if (requested_component_list.AddStringToArray(IDString) == nullptr) {
                return nullptr;
            }
        }
    }

    /* Convert to message buffer. */
    const char* message = json_dumps(response, 0);
    return message;
}
#endif

static void AddComponentIdToMap(QCBOREncodeContext* context, TrustedComponent* tc)
{
    QCBOREncode_OpenArrayInMapN(context, TEEP_LABEL_COMPONENT_ID);
    {
        UsefulBuf tc_id = UsefulBuf_FROM_BYTE_ARRAY(tc->ID.b);
        QCBOREncode_AddBytes(context, UsefulBuf_Const(tc_id));
    }
    QCBOREncode_CloseArray(context);
}

// Parse QueryRequest and compose QueryResponse.
static teep_error_code_t TeepComposeCborQueryResponse(QCBORDecodeContext* decodeContext, UsefulBufC* encoded, std::ostream& errorMessage)
{
    UsefulBufC challenge = NULLUsefulBufC;
    encoded->ptr = nullptr;
    encoded->len = 0;

    int maxBufferLength = 4096;
    char* rawBuffer = (char*)malloc(maxBufferLength);
    if (rawBuffer == nullptr) {
        errorMessage << "Out of memory";
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    encoded->ptr = rawBuffer;
    encoded->len = maxBufferLength;

    QCBOREncodeContext context;
    UsefulBuf buffer = UsefulBuf_Unconst(*encoded);
    QCBOREncode_Init(&context, buffer);

    QCBOREncode_OpenArray(&context);
    {
        // Add TYPE.
        QCBOREncode_AddInt64(&context, TEEP_MESSAGE_QUERY_RESPONSE);

        QCBORItem item;

        // Parse the QueryRequest options map.
        QCBORDecode_GetNext(decodeContext, &item);
        if (item.uDataType != QCBOR_TYPE_MAP) {
            REPORT_TYPE_ERROR(errorMessage, "options", QCBOR_TYPE_MAP, item);
            return TEEP_ERR_PERMANENT_ERROR;
        }

        QCBOREncode_OpenMap(&context);
        {
            uint16_t mapEntryCount = item.val.uCount;
            for (uint16_t mapIndex = 0; mapIndex < mapEntryCount; mapIndex++) {
                QCBORDecode_GetNext(decodeContext, &item);
                if (item.uLabelType != QCBOR_TYPE_INT64) {
                    return TEEP_ERR_PERMANENT_ERROR;
                }
                switch (item.label.int64) {
                case TEEP_LABEL_TOKEN:
                    // Copy token from QueryRequest into QueryResponse.
                    if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                        REPORT_TYPE_ERROR(errorMessage, "token", QCBOR_TYPE_BYTE_STRING, item);
                        return TEEP_ERR_PERMANENT_ERROR;
                    }
                    QCBOREncode_AddBytesToMapN(&context, TEEP_LABEL_TOKEN, item.val.string);
                    break;
                case TEEP_LABEL_SUPPORTED_CIPHER_SUITES:
                    if (item.uDataType != QCBOR_TYPE_ARRAY) {
                        REPORT_TYPE_ERROR(errorMessage, "supported-cipher-suites", QCBOR_TYPE_ARRAY, item);
                        return TEEP_ERR_PERMANENT_ERROR;
                    }
                    // TODO: read supported cipher suites and potentially
                    // add selected-cipher-suite to the QueryResponse.
                    printf("TODO: read supported cipher suites\n");
                    break;
                case TEEP_LABEL_SUPPORTED_FRESHNESS_MECHANISMS:
                {
                    if (item.uDataType != QCBOR_TYPE_ARRAY) {
                        REPORT_TYPE_ERROR(errorMessage, "supported-freshness-mechanisms", QCBOR_TYPE_ARRAY, item);
                        return TEEP_ERR_PERMANENT_ERROR;
                    }
                    uint16_t arrayEntryCount = item.val.uCount;
                    bool isNonceSupported = false;
                    for (uint16_t arrayIndex = 0; arrayIndex < arrayEntryCount; arrayIndex++) {
                        QCBORDecode_GetNext(decodeContext, &item);
                        if (item.uDataType != QCBOR_TYPE_INT64) {
                            REPORT_TYPE_ERROR(errorMessage, "freshness-mechanism", QCBOR_TYPE_INT64, item);
                            return TEEP_ERR_PERMANENT_ERROR;
                        }
                        if (item.val.int64 == TEEP_FRESHNESS_MECHANISM_NONCE) {
                            isNonceSupported = true;
                            printf("Choosing Nonce freshness mechanism\n");
                        }
                    }
                    if (!isNonceSupported) {
                        errorMessage << "No freshness mechanism in common, TEEP Agent only supports Nonce" << std::endl;
                        return TEEP_ERR_UNSUPPORTED_FRESHNESS_MECHANISM;
                    }
                    break;
                }
                case TEEP_LABEL_CHALLENGE:
                    // Save challenge for use with attestation call.
                    challenge = item.val.string;
                    break;
                case TEEP_LABEL_VERSIONS:
                    printf("TODO: read versions\n");
                    // TODO: read supported versions and potentially
                    // add selected-version to the QueryResponse.
                    break;
                case TEEP_LABEL_OCSP_DATA:
                    printf("TODO: read OCSP data\n");
                    break;
                }
            }

            // Parse the data-item-requested.
            QCBORDecode_GetNext(decodeContext, &item);
            if (item.uDataType != QCBOR_TYPE_INT64) {
                REPORT_TYPE_ERROR(errorMessage, "data-item-requested", QCBOR_TYPE_INT64, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            if (item.val.int64 & TEEP_ATTESTATION) {
                // Add evidence.
                // TODO(issue #9): get actual evidence via ctoken library or OE.
                UsefulBufC evidence = UsefulBuf_FROM_SZ_LITERAL("dummy value");
                QCBOREncode_AddBytesToMapN(&context, TEEP_LABEL_EVIDENCE, evidence);
            }
            if (item.val.int64 & TEEP_TRUSTED_COMPONENTS) {
                // Add tc-list.  Currently we populate this from the list of
                // "unneeded" components since most TEEs (like SGX) can't enumerate
                // any others anyway.
                QCBOREncode_OpenArrayInMapN(&context, TEEP_LABEL_TC_LIST);
                {
                    for (TrustedComponent* ta = g_UnneededComponentList; ta != nullptr; ta = ta->Next) {
                        QCBOREncode_OpenMap(&context);
                        {
                            AddComponentIdToMap(&context, ta);
                        }
                        QCBOREncode_CloseMap(&context);
                    }
                }
                QCBOREncode_CloseArray(&context);
            }
            if (item.val.int64 & TEEP_EXTENSIONS) {
                // Add ext-list to QueryResponse
                QCBOREncode_OpenArrayInMapN(&context, TEEP_LABEL_EXT_LIST);
                {
                    // We don't support any extensions currently.
                }
                QCBOREncode_CloseArray(&context);
            }

            if (g_RequestedComponentList != nullptr)
            {
                // Add requested-tc-list.
                QCBOREncode_OpenArrayInMapN(&context, TEEP_LABEL_REQUESTED_TC_LIST);
                {
                    for (TrustedComponent* ta = g_RequestedComponentList; ta != nullptr; ta = ta->Next) {
                        QCBOREncode_OpenMap(&context);
                        {
                            AddComponentIdToMap(&context, ta);
                        }
                        QCBOREncode_CloseMap(&context);
                    }
                }
                QCBOREncode_CloseArray(&context);
            }

            if (g_UnneededComponentList != nullptr)
            {
                // Add unneeded-tc-list.
                QCBOREncode_OpenArrayInMapN(&context, TEEP_LABEL_UNNEEDED_TC_LIST);
                {
                    for (TrustedComponent* tc = g_UnneededComponentList; tc != nullptr; tc = tc->Next) {
                        QCBOREncode_OpenArray(&context);
                        {
                            UsefulBuf tc_id = UsefulBuf_FROM_BYTE_ARRAY(tc->ID.b);
                            QCBOREncode_AddBytes(&context, UsefulBuf_Const(tc_id));
                        }
                        QCBOREncode_CloseArray(&context);
                    }
                }
                QCBOREncode_CloseArray(&context);
            }
        }
        QCBOREncode_CloseMap(&context);
    }
    QCBOREncode_CloseArray(&context);

    QCBORError err = QCBOREncode_Finish(&context, encoded);
    return (err == QCBOR_SUCCESS) ? TEEP_ERR_SUCCESS : TEEP_ERR_TEMPORARY_ERROR;
}

teep_error_code_t TeepSendCborMessage(void* sessionHandle, const char* mediaType, const char* buffer, size_t bufferlen)
{
    // From draft-ietf-teep-protocol section 4.1.1:
    // 1.  Create a TEEP message according to the description below and
    //     populate it with the respective content.  (done by caller)
    // 2.  Create a COSE Header containing the desired set of Header
    //     Parameters.  The COSE Header MUST be valid per the [RFC8152]
    //     specification.
    // ... TODO(issue #8) ...

    // 3.  Create a COSE_Sign1 object using the TEEP message as the
    //     COSE_Sign1 Payload; all steps specified in [RFC8152] for creating
    //     a COSE_Sign1 object MUST be followed.
    // ... TODO(issue #8) ...

    // 4.  Prepend the COSE object with the TEEP CBOR tag to indicate that
    //     the CBOR-encoded message is indeed a TEEP message.
    // TODO: see https://github.com/ietf-teep/teep-protocol/issues/147

    return QueueOutboundTeepMessage(sessionHandle, mediaType, buffer, bufferlen);
}

static teep_error_code_t TeepHandleCborQueryRequest(void* sessionHandle, QCBORDecodeContext* context)
{
    printf("TeepHandleCborQueryRequest\n");

    /* 3. Compose a raw response. */
    UsefulBufC queryResponse;
    std::ostringstream errorMessage;
    teep_error_code_t err = TeepComposeCborQueryResponse(context, &queryResponse, errorMessage);
    if (err != TEEP_ERR_SUCCESS) {
        // TODO: see https://github.com/ietf-teep/teep-protocol/issues/129
        // TeepSendError(token, sessionHandle, err, errorMessage.str());
        return err;
    }
    if (queryResponse.len == 0) {
        return TEEP_ERR_PERMANENT_ERROR;
    }

    printf("Sending CBOR message: ");
    HexPrintBuffer(queryResponse.ptr, queryResponse.len);

    printf("Sending QueryResponse...\n");

    err = TeepSendCborMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, (const char*)queryResponse.ptr, queryResponse.len);
    free((void*)queryResponse.ptr);
    return err;
}

#ifdef TEEP_ENABLE_JSON
// Returns 0 on success, non-zero on error.
int TeepHandleJsonQueryRequest(void* sessionHandle, json_t* object)
{
    int err = 1;
    oe_result_t result;

    printf("TeepHandleJsonQueryRequest\n");
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
    const char* message = TeepComposeJsonQueryResponse(object);

    printf("Sending QueryResponse: %s\n\n", message);

    result = ocall_QueueOutboundTeepMessage(&err, sessionHandle, TEEP_JSON_MEDIA_TYPE, message, strlen(message));
    free((void*)message);
    if (result != OE_OK) {
        return result;
    }
    return 0;
}

/* Compose a TEEP Success message. */
const char* TeepComposeJsonSuccess(
    const json_t* request)    // Request we're responding to.
{
    JsonAuto response(json_object(), true);
    if (response == nullptr) {
        return nullptr;
    }
    if (response.AddIntegerToObject("TYPE", TEEP_MESSAGE_SUCCESS) == nullptr) {
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
const char* TeepComposeJsonError(
    const json_t* request,    // Request we're responding to.
    int errorCode)
{
    JsonAuto response(json_object(), true);
    if (response == nullptr) {
        return nullptr;
    }
    if (response.AddIntegerToObject("TYPE", TEEP_MESSAGE_ERROR) == nullptr) {
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
int TeepHandleJsonInstall(void* sessionHandle, json_t* request)
{
    printf("TeepHandleJsonInstall\n");

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
    const char* message = TeepComposeJsonSuccess(request);
    printf("Sending Success: %s\n\n", message);
#else
    const char* message = TeepComposeJsonError(request, TEEP_ERR_INTERNAL_ERROR);
    printf("Sending Error: %s\n\n", message);
#endif

    result = ocall_QueueOutboundTeepMessage(&err, sessionHandle, OTRP_JSON_MEDIA_TYPE, message, strlen(message));
    free((void*)message);
    if (result != OE_OK) {
        return result;
    }
    return 0;
}
#endif

/* Compose a raw Success message to be signed. */
teep_error_code_t TeepComposeCborSuccess(UsefulBufC token, UsefulBufC* encoded)
{
    encoded->ptr = nullptr;
    encoded->len = 0;

    int maxBufferLength = 4096;
    char* rawBuffer = (char*)malloc(maxBufferLength);
    if (rawBuffer == nullptr) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    encoded->ptr = rawBuffer;
    encoded->len = maxBufferLength;

    QCBOREncodeContext context;
    UsefulBuf buffer = UsefulBuf_Unconst(*encoded);
    QCBOREncode_Init(&context, buffer);

    QCBOREncode_OpenArray(&context);
    {
        // Add TYPE.
        QCBOREncode_AddInt64(&context, TEEP_MESSAGE_SUCCESS);

        // Add option map.
        QCBOREncode_OpenMap(&context);
        {
            if (!UsefulBuf_IsNULLC(token)) {
                // Copy token from request.
                QCBOREncode_AddBytesToMapN(&context, TEEP_LABEL_TOKEN, token);
            }
        }
        QCBOREncode_CloseMap(&context);
    }
    QCBOREncode_CloseArray(&context);

    QCBORError err = QCBOREncode_Finish(&context, encoded);
    return (err == QCBOR_SUCCESS) ? TEEP_ERR_SUCCESS : TEEP_ERR_TEMPORARY_ERROR;
}

teep_error_code_t TeepComposeCborError(UsefulBufC token, teep_error_code_t errorCode, const std::string& errorMessage, UsefulBufC* encoded)
{
    encoded->ptr = nullptr;
    encoded->len = 0;

    int maxBufferLength = 4096;
    char* rawBuffer = (char*)malloc(maxBufferLength);
    if (rawBuffer == nullptr) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    encoded->ptr = rawBuffer;
    encoded->len = maxBufferLength;

    QCBOREncodeContext context;
    UsefulBuf buffer = UsefulBuf_Unconst(*encoded);
    QCBOREncode_Init(&context, buffer);

    QCBOREncode_OpenArray(&context);
    {
        // Add TYPE.
        QCBOREncode_AddInt64(&context, TEEP_MESSAGE_ERROR);

        QCBOREncode_OpenMap(&context);
        {
            if (!UsefulBuf_IsNULLC(token)) {
                // Copy token from request.
                QCBOREncode_AddBytesToMapN(&context, TEEP_LABEL_TOKEN, token);
            }

            // Add error message.
            if (!errorMessage.empty()) {
                QCBOREncode_AddSZStringToMapN(&context, TEEP_LABEL_ERR_MSG, errorMessage.c_str());
            }

            // Add suit-reports if Update failed.
            // TODO(issue #11): Add suit-reports.
        }
        QCBOREncode_CloseMap(&context);

        // Add err-code uint.
        QCBOREncode_AddInt64(&context, errorCode);
    }
    QCBOREncode_CloseArray(&context);

    QCBORError err = QCBOREncode_Finish(&context, encoded);
    return (err == QCBOR_SUCCESS) ? TEEP_ERR_SUCCESS : TEEP_ERR_TEMPORARY_ERROR;
}

void TeepSendError(UsefulBufC token, void* sessionHandle, teep_error_code_t errorCode, const std::string& errorMessage)
{
    UsefulBufC reply;
    if (TeepComposeCborError(token, errorCode, errorMessage, &reply) != TEEP_ERR_SUCCESS) {
        return;
    }
    if (reply.len == 0) {
        return;
    }

    printf("Sending CBOR message: ");
    HexPrintBuffer(reply.ptr, reply.len);

    (void)TeepSendCborMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, (const char*)reply.ptr, reply.len);
    free((void*)reply.ptr);
}

teep_error_code_t TeepHandleCborUpdate(void* sessionHandle, QCBORDecodeContext* context)
{
    printf("TeepHandleCborUpdate\n");

    std::ostringstream errorMessage;
    QCBORItem item;
    UsefulBufC token = NULLUsefulBufC;
    teep_error_code_t teeperr = TEEP_ERR_SUCCESS;

    // Parse the options map.
    QCBORDecode_GetNext(context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        REPORT_TYPE_ERROR(errorMessage, "options", QCBOR_TYPE_MAP, item);
        teeperr = TEEP_ERR_PERMANENT_ERROR;
        TeepSendError(token, sessionHandle, teeperr, errorMessage.str());
        return teeperr;
    }
    teep_error_code_t errorCode = TEEP_ERR_SUCCESS;
    uint16_t mapEntryCount = item.val.uCount;
    for (int mapEntryIndex = 0; mapEntryIndex < mapEntryCount; mapEntryIndex++) {
        QCBORDecode_GetNext(context, &item);
        teep_label_t label = (teep_label_t)item.label.int64;
        switch (label) {
        case TEEP_LABEL_TOKEN:
        {
            // Get token from request.
            if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                REPORT_TYPE_ERROR(errorMessage, "token", QCBOR_TYPE_BYTE_STRING, item);
                teeperr = TEEP_ERR_PERMANENT_ERROR;
                TeepSendError(token, sessionHandle, teeperr, errorMessage.str());
                return teeperr;
            }
            token = item.val.string;
            break;
        }
        case TEEP_LABEL_TC_LIST:
        {
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                REPORT_TYPE_ERROR(errorMessage, "tc-list", QCBOR_TYPE_ARRAY, item);
                teeperr = TEEP_ERR_PERMANENT_ERROR;
                TeepSendError(token, sessionHandle, teeperr, errorMessage.str());
                return teeperr;
            }
            uint16_t arrayEntryCount = item.val.uCount;
            for (int arrayEntryIndex = 0; arrayEntryIndex < arrayEntryCount; arrayEntryIndex++) {
                QCBORDecode_GetNext(context, &item);
                if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                    REPORT_TYPE_ERROR(errorMessage, "component-id", QCBOR_TYPE_BYTE_STRING, item);
                    teeperr = TEEP_ERR_PERMANENT_ERROR;
                    TeepSendError(token, sessionHandle, teeperr, errorMessage.str());
                    return teeperr;
                }
                /* TODO: do a delete */
            }
            break;
        }
        case TEEP_LABEL_MANIFEST_LIST:
        {
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                REPORT_TYPE_ERROR(errorMessage, "manifest-list", QCBOR_TYPE_ARRAY, item);
                teeperr = TEEP_ERR_PERMANENT_ERROR;
                TeepSendError(token, sessionHandle, teeperr, errorMessage.str());
                return teeperr;
            }
            uint16_t arrayEntryCount = item.val.uCount;
#ifdef _DEBUG
            printf("Parsing %d manifest-list entries...\n", item.val.uCount);
#endif
            for (int arrayEntryIndex = 0; arrayEntryIndex < arrayEntryCount; arrayEntryIndex++) {
                QCBORDecode_GetNext(context, &item);
                if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                    REPORT_TYPE_ERROR(errorMessage, "SUIT_Envelope", QCBOR_TYPE_BYTE_STRING, item);
                    teeperr = TEEP_ERR_PERMANENT_ERROR;
                    TeepSendError(token, sessionHandle, teeperr, errorMessage.str());
                    return teeperr;
                }
                if (errorCode == TEEP_ERR_SUCCESS) {
                    // Try until we hit the first error.
                    errorCode = TryProcessSuitEnvelope(item.val.string, errorMessage);
                }
            }
            break;
        }
        default:
            errorMessage << "Unrecognized option label " << label;
            teeperr = TEEP_ERR_PERMANENT_ERROR;
            TeepSendError(token, sessionHandle, teeperr, errorMessage.str());
            return teeperr;
        }
    }

    /* 3. Compose a Success reply. */
    UsefulBufC reply;
    teeperr = TeepComposeCborSuccess(token, &reply);
    if (teeperr != TEEP_ERR_SUCCESS) {
        return teeperr;
    }
    if (reply.len == 0) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }

    printf("Sending CBOR message: ");
    HexPrintBuffer(reply.ptr, reply.len);

    teeperr = TeepSendCborMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, (const char*)reply.ptr, reply.len);
    free((void*)reply.ptr);
    return teeperr;
}

#ifdef TEEP_ENABLE_JSON
int TeepHandleJsonDelete(void* sessionHandle, json_t* object)
{
    (void)sessionHandle; // Unused.
    (void)object; // Unused.

    printf("TeepHandleDelete\n");
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
    case TEEP_MESSAGE_QUERY_REQUEST:
        return TeepHandleJsonQueryRequest(sessionHandle, object);
    case TEEP_MESSAGE_INSTALL:
        return TeepHandleJsonInstall(sessionHandle, object);
    case TEEP_MESSAGE_DELETE:
        return TeepHandleJsonDelete(sessionHandle, object);
    default:
        // Not a legal message from the TAM.
        return 1;
    }
}
#endif

/* Handle an incoming message from a TEEP Agent. */
teep_error_code_t TeepHandleCborMessage(void* sessionHandle, const char* message, size_t messageLength)
{
    teep_error_code_t teeperr = TEEP_ERR_SUCCESS;
    std::ostringstream errorMessage;
    QCBORDecodeContext context;
    QCBORItem item;
    UsefulBufC encoded;
    encoded.ptr = message;
    encoded.len = messageLength;

    // From draft-ietf-teep-protocol section 4.1.2:
    //  1.  Verify that the received message is a valid CBOR object.
    //  2.  Remove the TEEP message CBOR tag and verify that one of the COSE
    //      CBOR tags follows it.
    // ... TODO(issue #8) ...

    //  3.  Verify that the message contains a COSE_Sign1 structure.
    // ... TODO(issue #8) ...

    //  4.  Verify that the resulting COSE Header includes only parameters
    //      and values whose syntax and semantics are both understood and
    //      supported or that are specified as being ignored when not
    //      understood.
    // ... TODO(issue #8) ...

    //  5.  Follow the steps specified in Section 4 of [RFC8152] ("Signing
    //      Objects") for validating a COSE_Sign1 object.  The COSE_Sign1
    //      payload is the content of the TEEP message.
    // ... TODO(issue #8) ...

    /*     Validate that the request TAM certificate is chained to a trusted
     *     CA that the TEE embeds as its trust anchor.
     *
     *     *  Cache the CA OCSP stapling data and certificate revocation
     *        check status for other subsequent requests.
     *
     *     *  A TEE can use its own clock time for the OCSP stapling data
     *        validation.
     *  TODO: teep protocol spec is missing above statements, closest
     *        thing is in ocsp-data description
     *  See https://github.com/ietf-teep/teep-protocol/issues/148
     */

    printf("Received CBOR message: ");
    HexPrintBuffer(encoded.ptr, encoded.len);

    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_ARRAY) {
        REPORT_TYPE_ERROR(errorMessage, "message", QCBOR_TYPE_ARRAY, item);
        return TEEP_ERR_PERMANENT_ERROR;
    }

    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_INT64) {
        REPORT_TYPE_ERROR(errorMessage, "TYPE", QCBOR_TYPE_INT64, item);
        return TEEP_ERR_PERMANENT_ERROR;
    }

    teep_message_type_t messageType = (teep_message_type_t)item.val.uint64;
    printf("Received CBOR TEEP message type=%d\n", messageType);
    switch (messageType) {
    case TEEP_MESSAGE_QUERY_REQUEST:
        teeperr = TeepHandleCborQueryRequest(sessionHandle, &context);
        break;
    case TEEP_MESSAGE_UPDATE:
        teeperr = TeepHandleCborUpdate(sessionHandle, &context);
        break;
    default:
        teeperr = TEEP_ERR_PERMANENT_ERROR;
        break;
    }
    if (teeperr != TEEP_ERR_SUCCESS) {
        return teeperr;
    }

    QCBORError err = QCBORDecode_Finish(&context);
    return (err == QCBOR_SUCCESS) ? TEEP_ERR_SUCCESS : TEEP_ERR_TEMPORARY_ERROR;
}

#ifdef TEEP_ENABLE_JSON
/* Handle an incoming message from a TEEP Agent. */
/* Returns 0 on success, or non-zero if error. */
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
#endif

int RequestTA(
    int useCbor,
    teep_uuid_t requestedTaid,
    const char* tamUri)
{
    teep_error_code_t err = TEEP_ERR_SUCCESS;

    // TODO: See whether requestedTaid is already installed.
    // For now we skip this step and pretend it's not.
    bool isInstalled = false;

    if (isInstalled) {
        // Already installed, nothing to do.
        // This counts as "pass no data back" in the broker spec.
        return 0;
    }

    // See whether requestedTaid has already been requested.
    TrustedComponent* tc;
    for (tc = g_RequestedComponentList; tc != nullptr; tc = tc->Next) {
        if (memcmp(tc->ID.b, requestedTaid.b, TEEP_UUID_SIZE) == 0) {
            // Already requested, nothing to do.
            // This counts as "pass no data back" in the broker spec.
            return 0;
        }
    }

    // Add requestedTaid to the request list.
    tc = new TrustedComponent(requestedTaid);
    tc->Next = g_RequestedComponentList;
    g_RequestedComponentList = tc;

    // TODO: we may want to modify the TAM URI here.

    // TODO: see whether we already have a TAM cert we trust.
    // For now we skip this step and say we don't.
    bool haveTrustedTamCert = false;

    if (!haveTrustedTamCert) {
        // Pass back a TAM URI with no buffer.
        printf("Sending an empty message...\n");
#ifdef TEEP_ENABLE_JSON
        const char* acceptMediaType = (useCbor) ? TEEP_CBOR_MEDIA_TYPE : TEEP_JSON_MEDIA_TYPE;
#else
        if (!useCbor) {
            return 1; /* Error */
        }
        const char* acceptMediaType = TEEP_CBOR_MEDIA_TYPE;
#endif
        int error = Connect(tamUri, acceptMediaType);
        if (error != 0) {
            return error;
        }
    } else {
        // TODO: implement going on to the next message.
        TEEP_ASSERT(false);
    }

    return err;
}

int UnrequestTA(
    int useCbor,
    teep_uuid_t unneededTaid,
    const char* tamUri)
{
    teep_error_code_t err = TEEP_ERR_SUCCESS;

    // TODO: See whether unneededTaid is installed.
    // For now we skip this step and pretend it is.
    bool isInstalled = true;

    if (!isInstalled) {
        // Already not installed, nothing to do.
        // This counts as "pass no data back" in the broker spec.
        return 0;
    }

    // See whether unneededTaid has already been notified to the TAM.
    TrustedComponent* tc;
    for (tc = g_UnneededComponentList; tc != nullptr; tc = tc->Next) {
        if (memcmp(tc->ID.b, unneededTaid.b, TEEP_UUID_SIZE) == 0) {
            // Already requested, nothing to do.
            // This counts as "pass no data back" in the broker spec.
            return 0;
        }
    }

    // Add unneededTaid to the unneeded list.
    tc = new TrustedComponent(unneededTaid);
    tc->Next = g_UnneededComponentList;
    g_UnneededComponentList = tc;

    // TODO: we may want to modify the TAM URI here.

    // TODO: see whether we already have a TAM cert we trust.
    // For now we skip this step and say we don't.
    bool haveTrustedTamCert = false;

    if (!haveTrustedTamCert) {
        // Pass back a TAM URI with no buffer.
        printf("Sending an empty message...\n");
#ifdef TEEP_ENABLE_JSON
        const char* acceptMediaType = (useCbor) ? TEEP_CBOR_MEDIA_TYPE : TEEP_JSON_MEDIA_TYPE;
#else
        if (!useCbor) {
            return 1; /* Error */
        }
        const char* acceptMediaType = TEEP_CBOR_MEDIA_TYPE;
#endif
        int error = Connect(tamUri, acceptMediaType);
        if (error != 0) {
            return error;
        }
    } else {
        // TODO: implement going on to the next message.
        TEEP_ASSERT(false);
    }

    return err;
}

#ifdef TEEP_ENABLE_JSON
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
#endif
