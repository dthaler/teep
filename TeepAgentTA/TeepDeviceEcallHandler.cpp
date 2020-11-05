/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include "TeepAgent_t.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "TrustedComponent.h"
extern "C" {
#include "jansson.h"
#include "joseinit.h"
#include "jose/b64.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
#include "jose/jws.h"
#include "jose/openssl.h"
#include "../TeepCommonTALib/common.h"
#include "../TeepCommonTALib/otrp.h"
#include "../TeepCommonTALib/teep_protocol.h"
};
#include "../jansson/JsonAuto.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"
#include "TeepDeviceEcallHandler.h"
#include "SuitParser.h"

// List of Trusted Components requested.
TrustedComponent* g_RequestedComponentList = nullptr;

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

    /* Convert to message buffer. */
    const char* message = json_dumps(response, 0);
    return message;
}

// Returns 0 on success, non-zero on error.
int TeepComposeCborQueryResponseTBS(QCBORDecodeContext* decodeContext, UsefulBufC* encoded)
{
    encoded->ptr = nullptr;
    encoded->len = 0;

    int maxBufferLength = 4096;
    char* rawBuffer = (char*)malloc(maxBufferLength);
    if (rawBuffer == nullptr) {
        return 1; /* Error */
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

        // Copy token from request.
        QCBORItem item;
        QCBORDecode_GetNext(decodeContext, &item);
        if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
            printf("Invalid token type %d\n", item.uDataType);
            return 1; /* invalid message */
        }
        QCBOREncode_AddBytes(&context, item.val.string);

        // Parse the options map.
        QCBORDecode_GetNext(decodeContext, &item);
        if (item.uDataType != QCBOR_TYPE_MAP) {
            printf("Invalid options type %d\n", item.uDataType);
            return 1; /* invalid message */
        }

        // Parse the data-item-requested.
        QCBORDecode_GetNext(decodeContext, &item);
        if (item.uDataType != QCBOR_TYPE_INT64) {
            printf("Invalid data-item-requested type %d\n", item.uDataType);
            return 1; /* invalid message */
        }

        QCBOREncode_OpenMap(&context);
        {
            // TODO: Add tc-list.
            // UsefulBufC ta_id;
            // QCBOREncode_AddBytesToMapN(&context, TEEP_LABEL_TC_LIST, ta_id);

            // Add requested-tc-list
            QCBOREncode_OpenArrayInMapN(&context, TEEP_LABEL_REQUESTED_TC_LIST);
            {
                for (TrustedComponent* ta = g_RequestedComponentList; ta != nullptr; ta = ta->Next) {
                    QCBOREncode_OpenMap(&context);
                    {
                        UsefulBuf ta_id = UsefulBuf_FROM_BYTE_ARRAY(ta->ID.b);
                        QCBOREncode_AddBytesToMapN(&context, TEEP_LABEL_COMPONENT_ID, UsefulBuf_Const(ta_id));
                    }
                    QCBOREncode_CloseMap(&context);
                }
            }
            QCBOREncode_CloseArray(&context);
        }
        QCBOREncode_CloseMap(&context);
    }
    QCBOREncode_CloseArray(&context);

    QCBORError err = QCBOREncode_Finish(&context, encoded);
    return err;
}

// Returns 0 on success, non-zero on error.
int TeepComposeCborQueryResponse(QCBORDecodeContext* context, UsefulBufC* queryResponse)
{
    /* Compose a raw QueryResponse message to be signed. */
    return TeepComposeCborQueryResponseTBS(context, queryResponse);
}

// Returns 0 on success, non-zero on error.
int TeepHandleCborQueryRequest(void* sessionHandle, QCBORDecodeContext* context)
{
    printf("TeepHandleCborQueryRequest\n");

    /* 1.  Validate COSE message signing.  If it doesn't pass, an error message is returned. */
    /* ... TODO ... */

    /* 2.  Validate that the request TAM certificate is chained to a trusted
     *     CA that the TEE embeds as its trust anchor.
     *
     *     *  Cache the CA OCSP stapling data and certificate revocation
     *        check status for other subsequent requests.
     *
     *     *  A TEE can use its own clock time for the OCSP stapling data
     *        validation.
     */
     /* ... TODO ... */

    /* 3. Compose a response. */
    UsefulBufC queryResponse;
    int err = TeepComposeCborQueryResponse(context, &queryResponse);
    if (err != 0) {
        return err;
    }
    if (queryResponse.len == 0) {
        return 1; /* Error */
    }

    printf("Sending CBOR message: ");
    HexPrintBuffer(queryResponse.ptr, queryResponse.len);

    printf("Sending QueryResponse...\n");

    oe_result_t result = ocall_QueueOutboundTeepMessage(&err, sessionHandle, TEEP_CBOR_MEDIA_TYPE, (const char*)queryResponse.ptr, queryResponse.len);
    free((void*)queryResponse.ptr);
    if (result != OE_OK) {
        return result;
    }

    return err;
}

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

// Returns 0 on success, non-zero on error.
int TeepComposeCborSuccessTBS(QCBORDecodeContext* decodeContext, UsefulBufC* encoded)
{
    encoded->ptr = nullptr;
    encoded->len = 0;

    int maxBufferLength = 4096;
    char* rawBuffer = (char*)malloc(maxBufferLength);
    if (rawBuffer == nullptr) {
        return 1; /* Error */
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

        // Copy token from request.
        QCBORItem item;
        QCBORDecode_GetNext(decodeContext, &item);
        if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
            printf("Invalid token type %d\n", item.uDataType);
            return 1; /* invalid message */
        }
        QCBOREncode_AddBytes(&context, item.val.string);

        // Add option map.
        QCBOREncode_OpenMap(&context);
        {
        }
        QCBOREncode_CloseMap(&context);
    }
    QCBOREncode_CloseArray(&context);

    QCBORError err = QCBOREncode_Finish(&context, encoded);
    return err;
}

// Returns 0 on success, non-zero on error.
int TeepComposeCborErrorTBS(QCBORDecodeContext* decodeContext, teep_error_code_t errorCode, UsefulBufC* encoded)
{
    encoded->ptr = nullptr;
    encoded->len = 0;

    int maxBufferLength = 4096;
    char* rawBuffer = (char*)malloc(maxBufferLength);
    if (rawBuffer == nullptr) {
        return 1; /* Error */
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

        // Copy token from request.
        QCBORItem item;
        QCBORDecode_GetNext(decodeContext, &item);
        if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
            printf("Invalid token type %d\n", item.uDataType);
            return 1; /* invalid message */
        }
        QCBOREncode_AddBytes(&context, item.val.string);

        // Add err-code uint.
        QCBOREncode_AddInt64(&context, errorCode);
        
        QCBOREncode_OpenMap(&context);
        {
            // TODO: Add ta-list.
            // UsefulBufC ta_id;
            // QCBOREncode_AddBytesToMapN(&context, TEEP_LABEL_TC_LIST, ta_id);
        }
        QCBOREncode_CloseMap(&context);
    }
    QCBOREncode_CloseArray(&context);

    QCBORError err = QCBOREncode_Finish(&context, encoded);
    return err;
}

// Returns 0 on success, non-zero on error.
int TeepComposeCborSuccess(QCBORDecodeContext* context, UsefulBufC* reply)
{
    /* Compose a raw QueryResponse message to be signed. */
    return TeepComposeCborSuccessTBS(context, reply);
}

// Returns 0 on success, non-zero on error.
int TeepComposeCborError(QCBORDecodeContext* context, teep_error_code_t errorCode, UsefulBufC* reply)
{
    /* Compose a raw QueryResponse message to be signed. */
    return TeepComposeCborErrorTBS(context, errorCode, reply);
}

// Returns 0 on success, non-zero on error.
int TeepHandleCborInstall(void* sessionHandle, QCBORDecodeContext* context)
{
    printf("TeepHandleCborInstall\n");

    /* 1.  Validate COSE message signing.  If it doesn't pass, an error message is returned. */
    /* ... TODO ... */

    /* 2.  Validate that the request TAM certificate is chained to a trusted
     *     CA that the TEE embeds as its trust anchor.
     *
     *     *  Cache the CA OCSP stapling data and certificate revocation
     *        check status for other subsequent requests.
     *
     *     *  A TEE can use its own clock time for the OCSP stapling data
     *        validation.
     */
     /* ... TODO ... */

    // Get token from request.
    QCBORItem item;
    QCBORDecode_GetNext(context, &item);
    if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        printf("Invalid token type %d\n", item.uDataType);
        return 1; /* invalid message */
    }

    // Parse the options map.
    QCBORDecode_GetNext(context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        printf("Invalid options type %d\n", item.uDataType);
        return 1; /* invalid message */
    }
    teep_error_code_t errorCode = TEEP_ERR_SUCCESS;
    uint16_t mapEntryCount = item.val.uCount;
    for (int mapEntryIndex = 0; mapEntryIndex < mapEntryCount; mapEntryIndex++) {
        QCBORDecode_GetNext(context, &item);
        teep_label_t label = (teep_label_t)item.label.int64;
        switch (label) {
        case TEEP_LABEL_MANIFEST_LIST:
        {
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                printf("Invalid option type %d\n", item.uDataType);
                return 1; /* invalid message */
            }
            uint16_t arrayEntryCount = item.val.uCount;
            for (int arrayEntryIndex = 0; arrayEntryIndex < arrayEntryCount; arrayEntryIndex++) {
                QCBORDecode_GetNext(context, &item);
                if (item.uDataType != QCBOR_TYPE_MAP) {
                    printf("Invalid suit envelope type %d\n", item.uDataType);
                    return 1; /* invalid message */
                }
                if (errorCode == TEEP_ERR_SUCCESS) {
                    // Try until we hit the first error.
                    errorCode = TryProcessSuitEnvelope(context, item.val.uCount);
                }
            }
            break;
        }
        default:
            printf("Unrecognized option label %d\n", label);
            return 1; /* invalid message */
            break;
        }
    }

    /* 3. Compose a success or error reply. */
    UsefulBufC reply;
    int err = TeepComposeCborError(context, errorCode, &reply);
    //int err = TeepComposeCborSuccess(context, &reply);
    if (err != 0) {
        return err;
    }
    if (reply.len == 0) {
        return 1; /* Error */
    }

    printf("Sending CBOR message: ");
    HexPrintBuffer(reply.ptr, reply.len);

    oe_result_t result = ocall_QueueOutboundTeepMessage(&err, sessionHandle, TEEP_CBOR_MEDIA_TYPE, (const char*)reply.ptr, reply.len);
    free((void*)reply.ptr);
    if (result != OE_OK) {
        return result;
    }

    return err;
}

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

/* Handle an incoming message from a TEEP Agent. */
/* Returns 0 on success, or non-zero if error. */
int TeepHandleCborMessage(void* sessionHandle, const char* message, unsigned int messageLength)
{
    QCBORDecodeContext context;
    QCBORItem item;
    UsefulBufC encoded;
    encoded.ptr = message;
    encoded.len = messageLength;

    printf("Received CBOR message: ");
    HexPrintBuffer(encoded.ptr, encoded.len);

    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_ARRAY) {
        printf("Invalid TYPE type %d\n", item.uDataType);
        return 1; /* invalid message */
    }

    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_INT64) {
        printf("Invalid TYPE type %d\n", item.uDataType);
        return 1; /* invalid message */
    }

    teep_message_type_t messageType = (teep_message_type_t)item.val.uint64;
    printf("Received CBOR TEEP message type=%d\n", messageType);
    switch (messageType) {
    case TEEP_MESSAGE_QUERY_REQUEST:
        if (TeepHandleCborQueryRequest(sessionHandle, &context) != 0) {
            return 1;
        }
        break;
    case TEEP_MESSAGE_INSTALL:
        if (TeepHandleCborInstall(sessionHandle, &context) != 0) {
            return 1;
        }
        break;
    default:
        return 1; /* unknown message type */
        break;
    }

    QCBORError err = QCBORDecode_Finish(&context);
    return err;
}

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

int ecall_RequestTA(
    int useCbor,
    oe_uuid_t requestedTaid,
    const char* tamUri)
{
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

    // See whether taid has already been requested.
    TrustedComponent* ta;
    for (ta = g_RequestedComponentList; ta != nullptr; ta = ta->Next) {
        if (memcmp(ta->ID.b, requestedTaid.b, OE_UUID_SIZE) == 0) {
            // Already requested, nothing to do.
            // This counts as "pass no data back" in the broker spec.
            return 0;
        }
    }

    // Add taid to the request list.
    ta = new TrustedComponent(requestedTaid);
    ta->Next = g_RequestedComponentList;
    g_RequestedComponentList = ta;

    // TODO: we may want to modify the TAM URI here.

    // TODO: see whether we already have a TAM cert we trust.
    // For now we skip this step and say we don't.
    bool haveTrustedTamCert = false;

    if (!haveTrustedTamCert) {
        // Pass back a TAM URI with no buffer.
        printf("Sending an empty message...\n");
        const char* acceptMediaType = (useCbor) ? TEEP_CBOR_MEDIA_TYPE : TEEP_JSON_MEDIA_TYPE;
        result = ocall_Connect(&err, tamUri, acceptMediaType);
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