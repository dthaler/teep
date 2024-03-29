// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT

#include <dirent.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <string.h>
#include <string>
#include "TrustedComponent.h"
#include "teep_protocol.h"
#include "TeepAgentLib.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "TeepDeviceEcallHandler.h"
#include "SuitParser.h"
#include "AgentKeys.h"

static teep_error_code_t TeepAgentComposeError(UsefulBufC token, teep_error_code_t errorCode, const std::string& errorMessage, UsefulBufC* encoded);

// List of requested Trusted Components.
TrustedComponent* g_RequestedComponentList = nullptr;

// List of installed Trusted Components.
TrustedComponent* g_InstalledComponentList = nullptr;

// List of unneeded Trusted Components.
TrustedComponent* g_UnneededComponentList = nullptr;

teep_error_code_t
TeepAgentSignMessage(
    _In_ const UsefulBufC* unsignedMessage,
    _In_ UsefulBuf signedMessageBuffer,
    _Out_ UsefulBufC* signedMessage)
{
    struct t_cose_key key_pair;
    teep_signature_kind_t signatureKind;
    TeepAgentGetSigningKeyPair(&key_pair, &signatureKind);

    return teep_sign1_cbor_message(&key_pair, unsignedMessage, signedMessageBuffer, signatureKind, signedMessage);
}

// Process a transport error.
teep_error_code_t TeepAgentProcessError(_In_ void* sessionHandle)
{
    (void)sessionHandle;

    return TEEP_ERR_TEMPORARY_ERROR;
}

teep_error_code_t TeepAgentRequestPolicyCheck(_In_z_ const char* tamUri)
{
    teep_error_code_t err = TEEP_ERR_SUCCESS;

    // TODO: we may want to modify the TAM URI here.

    // TODO: see whether we already have a TAM cert we trust.
    // For now we skip this step and say we don't.
    bool haveTrustedTamCert = false;

    if (!haveTrustedTamCert) {
        // Pass back a TAM URI with no buffer.
        TeepLogMessage("Sending an empty message...\n");
        const char* acceptMediaType = TEEP_CBOR_MEDIA_TYPE;
        teep_error_code_t error = TeepAgentConnect(tamUri, acceptMediaType);
        if (error != TEEP_ERR_SUCCESS) {
            return error;
        }
    } else {
        // TODO: implement going on to the next message.
        TEEP_ASSERT(false);
    }

    return err;
}

static void AddComponentIdToMap(_Inout_ QCBOREncodeContext* context, _In_ TrustedComponent* tc)
{
    QCBOREncode_OpenArrayInMapN(context, TEEP_LABEL_COMPONENT_ID);
    {
        UsefulBuf tc_id = UsefulBuf_FROM_BYTE_ARRAY(tc->ID.b);
        QCBOREncode_AddBytes(context, UsefulBuf_Const(tc_id));
    }
    QCBOREncode_CloseArray(context);
}

// Parse QueryRequest and compose QueryResponse.
static teep_error_code_t TeepAgentComposeQueryResponse(_Inout_ QCBORDecodeContext* decodeContext, _Out_ UsefulBufC* encodedResponse, _Out_ UsefulBufC* errorResponse)
{
    UsefulBufC challenge = NULLUsefulBufC;
    *encodedResponse = NULLUsefulBufC;
    UsefulBufC errorToken = NULLUsefulBufC;
    std::ostringstream errorMessage;

    size_t maxBufferLength = 4096;
    char* rawBuffer = (char*)malloc(maxBufferLength);
    if (rawBuffer == nullptr) {
        return TeepAgentComposeError(errorToken, TEEP_ERR_TEMPORARY_ERROR, "Out of memory", errorResponse);
    }

    QCBOREncodeContext context;
    UsefulBuf buffer{ rawBuffer, maxBufferLength };
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
            return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
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
                        return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);

                    }
                    errorToken = item.val.string;
                    QCBOREncode_AddBytesToMapN(&context, TEEP_LABEL_TOKEN, item.val.string);
                    break;
                case TEEP_LABEL_SUPPORTED_FRESHNESS_MECHANISMS:
                {
                    if (item.uDataType != QCBOR_TYPE_ARRAY) {
                        REPORT_TYPE_ERROR(errorMessage, "supported-freshness-mechanisms", QCBOR_TYPE_ARRAY, item);
                        return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                    }
                    uint16_t arrayEntryCount = item.val.uCount;
                    bool isNonceSupported = false;
                    for (uint16_t arrayIndex = 0; arrayIndex < arrayEntryCount; arrayIndex++) {
                        QCBORDecode_GetNext(decodeContext, &item);
                        if (item.uDataType != QCBOR_TYPE_INT64) {
                            REPORT_TYPE_ERROR(errorMessage, "freshness-mechanism", QCBOR_TYPE_INT64, item);
                            return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                        }
                        if (item.val.int64 == TEEP_FRESHNESS_MECHANISM_NONCE) {
                            isNonceSupported = true;
                            TeepLogMessage("Choosing Nonce freshness mechanism\n");
                        }
                    }
                    if (!isNonceSupported) {
                        errorMessage << "No freshness mechanism in common, TEEP Agent only supports Nonce" << std::endl;
                        return TeepAgentComposeError(errorToken, TEEP_ERR_UNSUPPORTED_FRESHNESS_MECHANISMS, errorMessage.str(), errorResponse);
                    }
                    break;
                }
                case TEEP_LABEL_CHALLENGE:
                    // Save challenge for use with attestation call.
                    challenge = item.val.string;
                    break;
                case TEEP_LABEL_VERSIONS:
                {
                    if (item.uDataType != QCBOR_TYPE_ARRAY) {
                        REPORT_TYPE_ERROR(errorMessage, "versions", QCBOR_TYPE_ARRAY, item);
                        return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                    }
                    uint16_t arrayEntryCount = item.val.uCount;
                    bool isVersion0Supported = false;
                    for (uint16_t arrayIndex = 0; arrayIndex < arrayEntryCount; arrayIndex++) {
                        QCBORDecode_GetNext(decodeContext, &item);
                        if (item.uDataType != QCBOR_TYPE_INT64) {
                            REPORT_TYPE_ERROR(errorMessage, "freshness-mechanism", QCBOR_TYPE_INT64, item);
                            return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                        }
                        if (item.val.int64 == 0) {
                            isVersion0Supported = true;
                        }
                    }
                    if (!isVersion0Supported) {
                        errorMessage << "No TEEP version in common, TEEP Agent only supports version 0" << std::endl;
                        return TeepAgentComposeError(errorToken, TEEP_ERR_UNSUPPORTED_MSG_VERSION, errorMessage.str(), errorResponse);
                    }
                    break;
                }
                }
            }

            // Parse the supported-teep-cipher-suites.
            {
                bool found = false;
                QCBORDecode_GetNext(decodeContext, &item);
                if (item.uDataType != QCBOR_TYPE_ARRAY) {
                    REPORT_TYPE_ERROR(errorMessage, "supported-teep-cipher-suites", QCBOR_TYPE_ARRAY, item);
                    return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                }
                uint16_t cipherSuiteCount = item.val.uCount;
                for (uint16_t cipherSuiteIndex = 0; cipherSuiteIndex < cipherSuiteCount; cipherSuiteIndex++) {
                    // Parse an array of cipher suite operations.
                    QCBORDecode_GetNext(decodeContext, &item);
                    if (item.uDataType != QCBOR_TYPE_ARRAY) {
                        REPORT_TYPE_ERROR(errorMessage, "cipher suite operations", QCBOR_TYPE_ARRAY, item);
                        return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                    }
                    uint16_t operationCount = item.val.uCount;
                    for (uint16_t operationIndex = 0; operationIndex < operationCount; operationIndex++) {
                        // Parse an array that specifies an operation.
                        QCBORDecode_GetNext(decodeContext, &item);
                        if (item.uDataType != QCBOR_TYPE_ARRAY || item.val.uCount != 2) {
                            REPORT_TYPE_ERROR(errorMessage, "cipher suite operation pair", QCBOR_TYPE_ARRAY, item);
                            return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                        }
                        QCBORDecode_GetNext(decodeContext, &item);
                        if (item.uDataType != QCBOR_TYPE_INT64) {
                            REPORT_TYPE_ERROR(errorMessage, "cose type", QCBOR_TYPE_INT64, item);
                            return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                        }
                        int64_t coseType = item.val.int64;

                        QCBORDecode_GetNext(decodeContext, &item);
                        if (item.uDataType != QCBOR_TYPE_INT64) {
                            REPORT_TYPE_ERROR(errorMessage, "cose algorithm", QCBOR_TYPE_INT64, item);
                            return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                        }
                        int64_t coseAlgorithm = item.val.int64;
                        if (coseType == CBOR_TAG_COSE_SIGN1 &&
                            coseAlgorithm == T_COSE_ALGORITHM_ES256) {
                            found = true;
                        }
                    }
                }
                if (!found) {
                    // TODO: include teep-cipher-suite-sign1-es256 or eddsa depending on configuration.
                    return TEEP_ERR_UNSUPPORTED_CIPHER_SUITES;
                }
                // Add selected-cipher-suite to the QueryResponse.
                QCBOREncode_OpenArrayInMapN(&context, TEEP_LABEL_SELECTED_CIPHER_SUITE);
                {
                    // Add teep-operation-sign1-es256.
                    QCBOREncode_OpenArray(&context);
                    {
                        QCBOREncode_AddInt64(&context, CBOR_TAG_COSE_SIGN1);
                        QCBOREncode_AddInt64(&context, T_COSE_ALGORITHM_ES256);
                    }
                    QCBOREncode_CloseArray(&context);
                }
                QCBOREncode_CloseArray(&context);
            }

            // Parse the supported-eat-suit-cipher-suites.
            {
                bool found = false;
                QCBORDecode_GetNext(decodeContext, &item);
                if (item.uDataType != QCBOR_TYPE_ARRAY) {
                    REPORT_TYPE_ERROR(errorMessage, "supported-eat-suit-cipher-suites", QCBOR_TYPE_ARRAY, item);
                    return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                }
                uint16_t cipherSuiteCount = item.val.uCount;
                for (uint16_t cipherSuiteIndex = 0; cipherSuiteIndex < cipherSuiteCount; cipherSuiteIndex++) {
                    // Parse an array of cipher suite operations.
                    QCBORDecode_GetNext(decodeContext, &item);
                    if (item.uDataType != QCBOR_TYPE_ARRAY || item.val.uCount != 2) {
                        REPORT_TYPE_ERROR(errorMessage, "cipher suite operation pair", QCBOR_TYPE_ARRAY, item);
                        return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                    }
                    QCBORDecode_GetNext(decodeContext, &item);
                    if (item.uDataType != QCBOR_TYPE_INT64) {
                        REPORT_TYPE_ERROR(errorMessage, "cose type", QCBOR_TYPE_INT64, item);
                        return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                    }
                    int64_t coseAuthenticationAlgorithm = item.val.int64;

                    QCBORDecode_GetNext(decodeContext, &item);
                    if (item.uDataType != QCBOR_TYPE_INT64) {
                        REPORT_TYPE_ERROR(errorMessage, "cose algorithm", QCBOR_TYPE_INT64, item);
                        return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                    }

                    int64_t coseEncryptionAlgorithm = item.val.int64;
                    if (coseAuthenticationAlgorithm == T_COSE_ALGORITHM_ES256 &&
                        coseEncryptionAlgorithm == T_COSE_ALGORITHM_A128GCM) {
                        found = true;
                    }
                }
                if (!found) {
                    // TODO: include suit-sha256-es256-ecdh-a128gcm or suit-sha256-eddsa-ecdh-a128gcm depending on configuration.
                    return TEEP_ERR_UNSUPPORTED_CIPHER_SUITES;
                }
            }

            // Parse the data-item-requested.
            QCBORDecode_GetNext(decodeContext, &item);
            if (item.uDataType != QCBOR_TYPE_INT64) {
                REPORT_TYPE_ERROR(errorMessage, "data-item-requested", QCBOR_TYPE_INT64, item);
                return TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
            }
            if (item.val.int64 & TEEP_ATTESTATION) {
                // Add evidence.
                // TODO(issue #9): get actual evidence via ctoken library or OE.
                QCBOREncode_AddSZStringToMapN(&context, TEEP_LABEL_ATTESTATION_PAYLOAD_FORMAT, "text/plain");
                UsefulBufC evidence = UsefulBuf_FROM_SZ_LITERAL("dummy value");
                QCBOREncode_AddBytesToMapN(&context, TEEP_LABEL_ATTESTATION_PAYLOAD, evidence);
            }
            if (item.val.int64 & TEEP_TRUSTED_COMPONENTS) {
                // Add tc-list.
                QCBOREncode_OpenArrayInMapN(&context, TEEP_LABEL_TC_LIST);
                {
                    for (TrustedComponent* ta = g_InstalledComponentList; ta != nullptr; ta = ta->Next) {
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
                // Add unneeded-manifest-list.
                QCBOREncode_OpenArrayInMapN(&context, TEEP_LABEL_UNNEEDED_MANIFEST_LIST);
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

    UsefulBufC const_buffer = UsefulBuf_Const(buffer);
    QCBORError err = QCBOREncode_Finish(&context, &const_buffer);
    if (err != QCBOR_SUCCESS) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }

    *encodedResponse = const_buffer;
    return TEEP_ERR_SUCCESS;
}

static teep_error_code_t TeepAgentSendMessage(
    _In_ void* sessionHandle,
    _In_z_ const char* mediaType,
    _In_ const UsefulBufC* unsignedMessage)
{
#ifdef TEEP_USE_COSE
    UsefulBufC signedMessage;
    Q_USEFUL_BUF_MAKE_STACK_UB(signed_cose_buffer, 1000);
    teep_error_code_t error = TeepAgentSignMessage(unsignedMessage, signed_cose_buffer, &signedMessage);
    if (error != TEEP_ERR_SUCCESS) {
        return error;
    }

    const char* output_buffer = (const char*)signedMessage.ptr;
    size_t output_buffer_length = signedMessage.len;
#else
    const char* output_buffer = (const char*)unsignedMessage->ptr;
    size_t output_buffer_length = unsignedMessage->len;
#endif

    return TeepAgentQueueOutboundTeepMessage(
        sessionHandle,
        mediaType,
        output_buffer,
        output_buffer_length);
}

/* Compose a raw Success message to be signed. */
static teep_error_code_t TeepAgentComposeSuccess(UsefulBufC token, UsefulBufC* encoded)
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

static teep_error_code_t TeepAgentComposeError(UsefulBufC token, teep_error_code_t errorCode, const std::string& errorMessage, UsefulBufC* encoded)
{
    *encoded = NULLUsefulBufC;

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

    // On success we return the original errorCode here, which the caller
    // can propogate.
    return (err == QCBOR_SUCCESS) ? errorCode : TEEP_ERR_TEMPORARY_ERROR;
}

static void TeepAgentSendError(UsefulBufC reply, void* sessionHandle)
{
    if (reply.len == 0) {
        return;
    }

    HexPrintBuffer("Sending CBOR message: ", reply.ptr, reply.len);

    (void)TeepAgentSendMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, &reply);
    free((void*)reply.ptr);
}

static teep_error_code_t TeepAgentHandleInvalidMessage(_In_ void* sessionHandle, _In_ QCBORDecodeContext* context)
{
    TEEP_UNUSED(context);
    TeepLogMessage("TeepAgentHandleInvalidMessage\n");

    UsefulBufC errorResponse;
    UsefulBufC errorToken = NULLUsefulBufC;
    TeepAgentComposeError(errorToken, TEEP_ERR_PERMANENT_ERROR, "Invalid message", &errorResponse);
    if (errorResponse.len > 0) {
        TeepAgentSendError(errorResponse, sessionHandle);
    }
    return TEEP_ERR_PERMANENT_ERROR;
}

static teep_error_code_t TeepAgentHandleQueryRequest(void* sessionHandle, QCBORDecodeContext* context)
{
    TeepLogMessage("TeepAgentHandleQueryRequest\n");

    /* Compose a raw response. */
    UsefulBufC queryResponse;
    UsefulBufC errorResponse;
    teep_error_code_t errorCode = TeepAgentComposeQueryResponse(context, &queryResponse, &errorResponse);
    if (errorCode != TEEP_ERR_SUCCESS) {
        TeepAgentSendError(errorResponse, sessionHandle);
        return errorCode;
    }
    if (queryResponse.len == 0) {
        return TEEP_ERR_PERMANENT_ERROR;
    }

    HexPrintBuffer("Sending CBOR message: ", queryResponse.ptr, queryResponse.len);

    TeepLogMessage("Sending QueryResponse...\n");

    errorCode = TeepAgentSendMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, &queryResponse);
    free((void*)queryResponse.ptr);
    return errorCode;
}

static teep_error_code_t TeepAgentParseComponentId(
    _Inout_ QCBORDecodeContext* context,
    _In_ const QCBORItem* arrayItem,
    _Out_ UsefulBufC* componentId,
    _Out_ std::ostringstream& errorMessage)
{
    if (arrayItem->uDataType != QCBOR_TYPE_ARRAY) {
        REPORT_TYPE_ERROR(errorMessage, "component-id", QCBOR_TYPE_ARRAY, *arrayItem);
        return TEEP_ERR_PERMANENT_ERROR;
    }

    // Get array size.
    uint16_t componentIdEntryCount = arrayItem->val.uCount;
    if (componentIdEntryCount != 1) {
        // TODO: support more general component ids.
        return TEEP_ERR_PERMANENT_ERROR;
    }

    // Read bstr from component id array.
    QCBORItem item;
    QCBORDecode_GetNext(context, &item);

    if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        REPORT_TYPE_ERROR(errorMessage, "component-id", QCBOR_TYPE_BYTE_STRING, item);
        return TEEP_ERR_PERMANENT_ERROR;
    }

    *componentId = item.val.string;
    return TEEP_ERR_SUCCESS;
}

static teep_error_code_t TeepAgentHandleUpdate(void* sessionHandle, QCBORDecodeContext* context)
{
    TeepLogMessage("TeepAgentHandleUpdate\n");

    std::ostringstream errorMessage;
    QCBORItem item;
    UsefulBufC token = NULLUsefulBufC;
    teep_error_code_t teep_error = TEEP_ERR_SUCCESS;
    UsefulBufC errorResponse = NULLUsefulBufC;

    // Parse the options map.
    QCBORDecode_GetNext(context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        REPORT_TYPE_ERROR(errorMessage, "options", QCBOR_TYPE_MAP, item);
        teep_error = TeepAgentComposeError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
        TeepAgentSendError(errorResponse, sessionHandle);
        return teep_error;
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
                teep_error = TeepAgentComposeError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
                TeepAgentSendError(errorResponse, sessionHandle);
                return teep_error;
            }
            token = item.val.string;
            break;
        }
        case TEEP_LABEL_UNNEEDED_MANIFEST_LIST:
        {
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                REPORT_TYPE_ERROR(errorMessage, "unneeded-manifest-list", QCBOR_TYPE_ARRAY, item);
                teep_error = TeepAgentComposeError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
                TeepAgentSendError(errorResponse, sessionHandle);
                return teep_error;
            }
            uint16_t arrayEntryCount = item.val.uCount;
#ifdef _DEBUG
            TeepLogMessage("Parsing %d unneeded-manifest-list entries...\n", item.val.uCount);
#endif
            for (int arrayEntryIndex = 0; arrayEntryIndex < arrayEntryCount; arrayEntryIndex++) {
                QCBORDecode_GetNext(context, &item);
                UsefulBufC componentId;
                teep_error = TeepAgentParseComponentId(context, &item, &componentId, errorMessage);
                if (teep_error != TEEP_ERR_SUCCESS) {
                    teep_error = TeepAgentComposeError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
                    TeepAgentSendError(errorResponse, sessionHandle);
                    return teep_error;
                }
                errorCode = SuitUninstallComponent(componentId);
                if (errorCode != TEEP_ERR_SUCCESS) {
                    break;
                }
            }
            break;
        }
        case TEEP_LABEL_MANIFEST_LIST:
        {
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                REPORT_TYPE_ERROR(errorMessage, "manifest-list", QCBOR_TYPE_ARRAY, item);
                teep_error = TeepAgentComposeError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
                TeepAgentSendError(errorResponse, sessionHandle);
                return teep_error;
            }
            uint16_t arrayEntryCount = item.val.uCount;
#ifdef _DEBUG
            TeepLogMessage("Parsing %d manifest-list entries...\n", item.val.uCount);
#endif
            for (int arrayEntryIndex = 0; arrayEntryIndex < arrayEntryCount; arrayEntryIndex++) {
                QCBORDecode_GetNext(context, &item);
                if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                    REPORT_TYPE_ERROR(errorMessage, "SUIT_Envelope", QCBOR_TYPE_BYTE_STRING, item);
                    teep_error = TeepAgentComposeError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
                    TeepAgentSendError(errorResponse, sessionHandle);
                    return teep_error;
                }
                if (errorCode == TEEP_ERR_SUCCESS) {
                    // Try until we hit the first error.
                    errorCode = TryProcessSuitEnvelope(item.val.string, errorMessage);
                    if (errorCode != TEEP_ERR_SUCCESS) {
                        break;
                    }
                }
            }
            break;
        }
        case TEEP_LABEL_ATTESTATION_PAYLOAD_FORMAT:
        {
            if (item.uDataType != QCBOR_TYPE_TEXT_STRING) {
                REPORT_TYPE_ERROR(errorMessage, "attestation-payload-format", QCBOR_TYPE_TEXT_STRING, item);
                teep_error = TeepAgentComposeError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
                TeepAgentSendError(errorResponse, sessionHandle);
                return teep_error;
            }
            // TODO: use Attestation Result.
            break;
        }
        case TEEP_LABEL_ATTESTATION_PAYLOAD:
        {
            if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                REPORT_TYPE_ERROR(errorMessage, "attestation-payload", QCBOR_TYPE_BYTE_STRING, item);
                teep_error = TeepAgentComposeError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
                TeepAgentSendError(errorResponse, sessionHandle);
                return teep_error;
            }
            // TODO: use Attestation Result.
            break;
        }
        case TEEP_LABEL_ERR_CODE:
        {
            if (item.uDataType != QCBOR_TYPE_INT64) {
                REPORT_TYPE_ERROR(errorMessage, "err-code", QCBOR_TYPE_INT64, item);
                teep_error = TeepAgentComposeError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
                TeepAgentSendError(errorResponse, sessionHandle);
                return teep_error;
            }
            errorMessage << "err-code: " << item.val.int64 << std::endl;
            TeepLogMessage(errorMessage.str().c_str());
            break;
        }
        case TEEP_LABEL_ERR_MSG:
        {
            if (item.uDataType != QCBOR_TYPE_TEXT_STRING) {
                REPORT_TYPE_ERROR(errorMessage, "err-msg", QCBOR_TYPE_TEXT_STRING, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            errorMessage << "err-msg: " << std::string((const char*)item.val.string.ptr, item.val.string.len) << std::endl;
            TeepLogMessage(errorMessage.str().c_str());
            break;
        }
        default:
            errorMessage << "Unrecognized option label " << label;
            teep_error = TeepAgentComposeError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
            TeepAgentSendError(errorResponse, sessionHandle);
            return teep_error;
        }
    }

    /* Compose a Success reply. */
    UsefulBufC reply;
    teep_error = TeepAgentComposeSuccess(token, &reply);
    if (teep_error != TEEP_ERR_SUCCESS) {
        return teep_error;
    }
    if (reply.len == 0) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }

    HexPrintBuffer("Sending CBOR message: ", reply.ptr, reply.len);

    teep_error = TeepAgentSendMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, &reply);
    free((void*)reply.ptr);
    return teep_error;
}

static teep_error_code_t TeepAgentVerifyMessageSignature(
    _In_ void* sessionHandle,
    _In_reads_(messageLength) const char* message,
    size_t messageLength,
    _Out_ UsefulBufC* pencoded)
{
    TEEP_UNUSED(sessionHandle);
    UsefulBufC signed_cose;
    signed_cose.ptr = message;
    signed_cose.len = messageLength;
    for (auto [kind, key_pair] : TeepAgentGetTamKeys()) {
        teep_error_code_t teeperr = teep_verify_cbor_message(kind, &key_pair, &signed_cose, pencoded);
        if (teeperr == TEEP_ERR_SUCCESS) {
            // TODO(#114): save key_pair in session
            return TEEP_ERR_SUCCESS;
        }
    }
    TeepLogMessage("TEEP agent failed verification of TAM key\n");
    return TEEP_ERR_PERMANENT_ERROR;

#if 0
#ifdef TEEP_USE_COSE
    // Determine whether message is COSE_Sign1 or not.
    if ((messageLength >= 2) && (message[0] == (char)0x84) && (message[1] == TEEP_MESSAGE_QUERY_REQUEST)) {
        // The only message that isn't is a query request where
        // the first byte means array of size 4 and the second byte is a 1.
#endif
        encoded.ptr = message;
        encoded.len = messageLength;
#ifdef TEEP_USE_COSE
    } else {
        struct t_cose_key key_pair;
        teeperr = TeepAgentGetTamKey(&key_pair);
        if (teeperr != TEEP_ERR_SUCCESS) {
            return teeperr;
        }

        UsefulBufC signed_cose;
        signed_cose.ptr = message;
        signed_cose.len = messageLength;
        teeperr = teep_verify_cbor_message(&key_pair, &signed_cose, pencoded);
        if (teeperr != TEEP_ERR_SUCCESS) {
            return teeperr;
        }
    }
#endif
#endif
}

/* Handle an incoming message from a TAM. */
static teep_error_code_t TeepAgentHandleMessage(
    _In_ void* sessionHandle,
    _In_reads_(messageLength) const char* message,
    size_t messageLength)
{
    QCBORDecodeContext context;
    QCBORItem item;
    std::ostringstream errorMessage;

    HexPrintBuffer("TeepAgentHandleCborMessage got COSE message:\n", message, messageLength);
    TeepLogMessage("\n");

    // Verify signature and save which signing key was used.
    UsefulBufC encoded;
    teep_error_code_t teeperr = TeepAgentVerifyMessageSignature(sessionHandle, message, messageLength, &encoded);
    if (teeperr != TEEP_ERR_SUCCESS) {
        return teeperr;
    }

    HexPrintBuffer("Received CBOR message: ", encoded.ptr, encoded.len);

    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_ARRAY) {
        REPORT_TYPE_ERROR(errorMessage, "message", QCBOR_TYPE_ARRAY, item);
        return TeepAgentHandleInvalidMessage(sessionHandle, &context);
    }

    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_INT64) {
        REPORT_TYPE_ERROR(errorMessage, "TYPE", QCBOR_TYPE_INT64, item);
        return TeepAgentHandleInvalidMessage(sessionHandle, &context);
    }

    teep_message_type_t messageType = (teep_message_type_t)item.val.uint64;
    TeepLogMessage("Received CBOR TEEP message type=%d\n", messageType);
    switch (messageType) {
    case TEEP_MESSAGE_QUERY_REQUEST:
        teeperr = TeepAgentHandleQueryRequest(sessionHandle, &context);
        break;
    case TEEP_MESSAGE_UPDATE:
        teeperr = TeepAgentHandleUpdate(sessionHandle, &context);
        break;
    default:
        teeperr = TeepAgentHandleInvalidMessage(sessionHandle, &context);
        break;
    }

    QCBORError err = QCBORDecode_Finish(&context);
    if (teeperr != TEEP_ERR_SUCCESS) {
        return teeperr;
    }
    return (err == QCBOR_SUCCESS) ? TEEP_ERR_SUCCESS : TEEP_ERR_TEMPORARY_ERROR;
}

teep_error_code_t TeepAgentProcessTeepMessage(
    _In_ void* sessionHandle,
    _In_z_ const char* mediaType,
    _In_reads_(messageLength) const char* message,
    size_t messageLength)
{
    teep_error_code_t err = TEEP_ERR_SUCCESS;

    TeepLogMessage("Received contentType='%s' messageLength=%zd\n", mediaType, messageLength);

    if (messageLength < 1) {
        return TEEP_ERR_PERMANENT_ERROR;
    }

    if (strncmp(mediaType, TEEP_CBOR_MEDIA_TYPE, strlen(TEEP_CBOR_MEDIA_TYPE)) == 0) {
        err = TeepAgentHandleMessage(sessionHandle, message, messageLength);
    } else {
        return TEEP_ERR_PERMANENT_ERROR;
    }

    return err;
}

static _Ret_maybenull_ TrustedComponent* FindComponentInList(_In_opt_ TrustedComponent* head, teep_uuid_t taid)
{
    for (TrustedComponent* ta = head; ta != nullptr; ta = ta->Next) {
        if (memcmp(&ta->ID, &taid, sizeof(taid)) == 0) {
            return ta;
        }
    }
    return nullptr;
}

teep_error_code_t TeepAgentRequestTA(
    teep_uuid_t requestedTaid,
    _In_z_ const char* tamUri)
{
    teep_error_code_t err = TEEP_ERR_SUCCESS;

    // See whether requestedTaid is already installed.
    TrustedComponent* found = FindComponentInList(g_InstalledComponentList, requestedTaid);
    if (found != nullptr) {
        // Already installed, nothing to do.
        // This counts as "pass no data back" in the broker spec.
        return TEEP_ERR_SUCCESS;
    }

    // See whether requestedTaid has already been requested.
    TrustedComponent* tc;
    for (tc = g_RequestedComponentList; tc != nullptr; tc = tc->Next) {
        if (memcmp(tc->ID.b, requestedTaid.b, TEEP_UUID_SIZE) == 0) {
            // Already requested, nothing to do.
            // This counts as "pass no data back" in the broker spec.
            return TEEP_ERR_SUCCESS;
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
        TeepLogMessage("Sending an empty message...\n");
        const char* acceptMediaType = TEEP_CBOR_MEDIA_TYPE;
        err = TeepAgentConnect(tamUri, acceptMediaType);
        if (err != TEEP_ERR_SUCCESS) {
            return err;
        }
    } else {
        // TODO: implement going on to the next message.
        TEEP_ASSERT(false);
    }

    return err;
}

teep_error_code_t TeepAgentUnrequestTA(
    teep_uuid_t unneededTaid,
    _In_z_ const char* tamUri)
{
    teep_error_code_t teep_error = TEEP_ERR_SUCCESS;

    // See whether unneededTaid is installed.
    TrustedComponent* found = FindComponentInList(g_InstalledComponentList, unneededTaid);
    if (found == nullptr) {
        // Already not installed, nothing to do.
        // This counts as "pass no data back" in the broker spec.
        return TEEP_ERR_SUCCESS;
    }

    // See whether unneededTaid has already been notified to the TAM.
    TrustedComponent* tc = FindComponentInList(g_UnneededComponentList, unneededTaid);
    if (tc != nullptr) {
        // Already requested, nothing to do.
        // This counts as "pass no data back" in the broker spec.
        return TEEP_ERR_SUCCESS;
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
        TeepLogMessage("Sending an empty message...\n");
        teep_error = TeepAgentConnect(tamUri, TEEP_CBOR_MEDIA_TYPE);
        if (teep_error != TEEP_ERR_SUCCESS) {
            return teep_error;
        }
    } else {
        // TODO: implement going on to the next message.
        TEEP_ASSERT(false);
    }

    return teep_error;
}

/* TODO: This is just a placeholder for a real implementation.
 * Currently we provide untrusted manifests into the TEEP Agent.
 * In a real implementation, the TEEP Agent would instead either load
 * manifests from a trusted location, or use sealed storage
 * (decrypting the contents inside the TEE).
 */
teep_error_code_t TeepAgentConfigureManifests(
    _In_z_ const char* directory_name)
{
    teep_error_code_t result = TEEP_ERR_SUCCESS;
    DIR* dir = opendir(directory_name);
    if (dir == NULL) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    for (;;) {
        struct dirent* dirent = readdir(dir);
        if (dirent == NULL) {
            break;
        }
        char* filename = dirent->d_name;
        size_t filename_length = strlen(filename);
        if (filename_length < 6 ||
            strcmp(filename + filename_length - 5, ".cbor") != 0) {
            continue;
        }

        // Convert filename to a uuid.
        teep_uuid_t component_id;
        result = GetUuidFromFilename(filename, &component_id);
        if (result != TEEP_ERR_SUCCESS) {
            break;
        }

        TrustedComponent* tc = new TrustedComponent(component_id);
        if (tc == nullptr) {
            result = TEEP_ERR_TEMPORARY_ERROR;
            break;
        }
        tc->Next = g_InstalledComponentList;
        g_InstalledComponentList = tc;
    }
    closedir(dir);
    return result;
}

filesystem::path g_agent_data_directory;

teep_error_code_t TeepAgentLoadConfiguration(_In_z_ const char* dataDirectory)
{
    g_agent_data_directory = std::filesystem::current_path();
    g_agent_data_directory /= dataDirectory;

    std::filesystem::path manifest_path = g_agent_data_directory / "manifests";
    return TeepAgentConfigureManifests(manifest_path.string().c_str());
}

static void ClearComponentList(_Inout_ TrustedComponent** componentList)
{
    while (*componentList != nullptr) {
        TrustedComponent* ta = *componentList;
        *componentList = ta->Next;
        ta->Next = nullptr;
        delete ta;
    }
}

void TeepAgentShutdown()
{
    ClearComponentList(&g_InstalledComponentList);
    ClearComponentList(&g_UnneededComponentList);
    ClearComponentList(&g_RequestedComponentList);
}

#define TOXDIGIT(x) ("0123456789abcdef"[x])

void TeepAgentMakeManifestFilename(_Out_ filesystem::path& manifestPath, _In_reads_(buffer_len) const char* buffer, size_t buffer_len)
{
    manifestPath = g_agent_data_directory;
    manifestPath /= "manifests";

    char filename[_MAX_PATH];
#if 1
    // Hex encode buffer.
    for (size_t i = 0, fi = 0; i < buffer_len; i++) {
        uint8_t ch = buffer[i];
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            filename[fi++] = '-';
        }
        filename[fi++] = TOXDIGIT(ch >> 4);
        filename[fi++] = TOXDIGIT(ch & 0xf);
        filename[fi] = 0;
    }
#else
    // Escape illegal characters.
    size_t i;
    for (i = 0; (i < buffer_len) && (i < filename_len - 1) && buffer[i]; i++) {
        filename[i] = (isalnum(buffer[i]) || (strchr("-_", buffer[i]) != nullptr)) ? buffer[i] : '-';
    }
    filename[i] = 0;
#endif

    manifestPath /= filename;
    manifestPath += ".cbor";
}
