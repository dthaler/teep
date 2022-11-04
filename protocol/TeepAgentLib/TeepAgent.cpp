// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT

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

// List of unneeded Trusted Components.
TrustedComponent* g_UnneededComponentList = nullptr;

const unsigned char* g_AgentDerCertificate = nullptr;
size_t g_AgentDerCertificateSize = 0;

_Ret_writes_bytes_maybenull_(pCertLen)
const unsigned char* GetAgentDerCertificate(size_t* pCertLen)
{
    if (g_AgentDerCertificate == nullptr) {
        // Construct a self-signed DER certificate based on the COSE key.
        t_cose_key key_pair;
        teep_error_code_t teep_error = TeepAgentGetSigningKeyPair(&key_pair);
        if (teep_error != TEEP_ERR_SUCCESS) {
            return nullptr;
        }

        g_AgentDerCertificate = GetDerCertificate(&key_pair, &g_AgentDerCertificateSize);
    }

    *pCertLen = g_AgentDerCertificateSize;
    return g_AgentDerCertificate;
}

teep_error_code_t
TeepAgentSignCborMessage(
    _In_ const UsefulBufC* unsignedMessage,
    _In_ UsefulBuf signedMessageBuffer,
    _Out_ UsefulBufC* signedMessage)
{
    struct t_cose_key key_pair;
    teep_error_code_t err = TeepAgentGetSigningKeyPair(&key_pair);
    if (err != TEEP_ERR_SUCCESS) {
        return err;
    }

    return teep_sign_cbor_message(key_pair, unsignedMessage, signedMessageBuffer, signedMessage);
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
static teep_error_code_t TeepAgentComposeQueryResponse(_In_ QCBORDecodeContext* decodeContext, _Out_ UsefulBufC* encodedResponse, _Out_ UsefulBufC* errorResponse)
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

            // Parse the supported-cipher-suites.
            {
                bool found = false;
                QCBORDecode_GetNext(decodeContext, &item);
                if (item.uDataType != QCBOR_TYPE_ARRAY) {
                    REPORT_TYPE_ERROR(errorMessage, "supported-cipher-suites", QCBOR_TYPE_ARRAY, item);
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
                    // TODO: include teep-cipher-suite-sign1-es256.
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

    UsefulBufC const_buffer = UsefulBuf_Const(buffer);
    QCBORError err = QCBOREncode_Finish(&context, &const_buffer);
    if (err != QCBOR_SUCCESS) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }

    *encodedResponse = const_buffer;
    return TEEP_ERR_SUCCESS;
}

teep_error_code_t TeepAgentSendCborMessage(
    _In_ void* sessionHandle,
    _In_z_ const char* mediaType,
    _In_ const UsefulBufC* unsignedMessage)
{
#ifdef TEEP_USE_COSE
    UsefulBufC signedMessage;
    Q_USEFUL_BUF_MAKE_STACK_UB(signed_cose_buffer, 1000);
    teep_error_code_t error = TeepAgentSignCborMessage(unsignedMessage, signed_cose_buffer, &signedMessage);
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

    (void)TeepAgentSendCborMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, &reply);
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

static teep_error_code_t TeepAgentHandleCborQueryRequest(void* sessionHandle, QCBORDecodeContext* context)
{
    TeepLogMessage("TeepAgentHandleCborQueryRequest\n");

    /* 3. Compose a raw response. */
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

    errorCode = TeepAgentSendCborMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, &queryResponse);
    free((void*)queryResponse.ptr);
    return errorCode;
}

teep_error_code_t TeepAgentHandleCborUpdate(void* sessionHandle, QCBORDecodeContext* context)
{
    TeepLogMessage("TeepAgentHandleCborUpdate\n");

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
        default:
            errorMessage << "Unrecognized option label " << label;
            teep_error = TeepAgentComposeError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
            TeepAgentSendError(errorResponse, sessionHandle);
            return teep_error;
        }
    }

    /* 3. Compose a Success reply. */
    UsefulBufC reply;
    teep_error = TeepAgentComposeSuccess(token, &reply);
    if (teep_error != TEEP_ERR_SUCCESS) {
        return teep_error;
    }
    if (reply.len == 0) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }

    HexPrintBuffer("Sending CBOR message: ", reply.ptr, reply.len);

    teep_error = TeepAgentSendCborMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, &reply);
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
    for (auto key_pair : TeepAgentGetTamKeys()) {
        teep_error_code_t teeperr = teep_verify_cbor_message(&key_pair, &signed_cose, pencoded);
        if (teeperr == TEEP_ERR_SUCCESS) {
            // TODO: save key_pair in session
            return TEEP_ERR_SUCCESS;
        }
    }
    TeepLogMessage("TAM key verification failed\n");
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
    }
    else {
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
static teep_error_code_t TeepAgentHandleCborMessage(
    _In_ void* sessionHandle,
    _In_reads_(messageLength) const char* message,
    size_t messageLength)
{
    QCBORDecodeContext context;
    QCBORItem item;
    std::ostringstream errorMessage;

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
        teeperr = TeepAgentHandleCborQueryRequest(sessionHandle, &context);
        break;
    case TEEP_MESSAGE_UPDATE:
        teeperr = TeepAgentHandleCborUpdate(sessionHandle, &context);
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
        err = TeepAgentHandleCborMessage(sessionHandle, message, messageLength);
    } else {
        return TEEP_ERR_PERMANENT_ERROR;
    }

    return err;
}

teep_error_code_t TeepAgentRequestTA(
    teep_uuid_t requestedTaid,
    _In_z_ const char* tamUri)
{
    teep_error_code_t err = TEEP_ERR_SUCCESS;

    // TODO: See whether requestedTaid is already installed.
    // For now we skip this step and pretend it's not.
    bool isInstalled = false;

    if (isInstalled) {
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

    // TODO: See whether unneededTaid is installed.
    // For now we skip this step and pretend it is.
    bool isInstalled = true;

    if (!isInstalled) {
        // Already not installed, nothing to do.
        // This counts as "pass no data back" in the broker spec.
        return TEEP_ERR_SUCCESS;
    }

    // See whether unneededTaid has already been notified to the TAM.
    TrustedComponent* tc;
    for (tc = g_UnneededComponentList; tc != nullptr; tc = tc->Next) {
        if (memcmp(tc->ID.b, unneededTaid.b, TEEP_UUID_SIZE) == 0) {
            // Already requested, nothing to do.
            // This counts as "pass no data back" in the broker spec.
            return TEEP_ERR_SUCCESS;
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

teep_error_code_t TeepAgentLoadConfiguration(_In_z_ const char* dataDirectory)
{
    TEEP_UNUSED(dataDirectory);
    return TEEP_ERR_SUCCESS;
}
