// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

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
#include <sstream>

static teep_error_code_t TeepAgentComposeCborError(UsefulBufC token, teep_error_code_t errorCode, const std::string& errorMessage, UsefulBufC* encoded);

// List of requested Trusted Components.
TrustedComponent* g_RequestedComponentList = nullptr;

// List of unneeded Trusted Components.
TrustedComponent* g_UnneededComponentList = nullptr;

#define TEEP_AGENT_SIGNING_PRIVATE_KEY_PAIR_FILENAME "teepagent-private-key-pair.pem"
#define TEEP_AGENT_SIGNING_PUBLIC_KEY_FILENAME "teepagent-public-key.pem"

static teep_error_code_t TeepAgentGetSigningKeyPair(struct t_cose_key* key_pair)
{
    return teep_get_signing_key_pair(key_pair, TEEP_AGENT_SIGNING_PRIVATE_KEY_PAIR_FILENAME, TEEP_AGENT_SIGNING_PUBLIC_KEY_FILENAME);
}

/* Get the TAM's public key to verify an incoming message against. */
teep_error_code_t TeepAgentGetTamKey(_Out_ struct t_cose_key* key_pair)
{
    return teep_get_verifying_key_pair(key_pair, TAM_SIGNING_PUBLIC_KEY_FILENAME);
}

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

// Process a transport error.
teep_error_code_t TeepAgentProcessError(void* sessionHandle)
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
        printf("Sending an empty message...\n");
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
static teep_error_code_t TeepAgentComposeCborQueryResponse(_In_ QCBORDecodeContext* decodeContext, _Out_ UsefulBufC* encodedResponse, _Out_ UsefulBufC* errorResponse)
{
    UsefulBufC challenge = NULLUsefulBufC;
    *encodedResponse = NULLUsefulBufC;
    UsefulBufC errorToken = NULLUsefulBufC;
    std::ostringstream errorMessage;

    int maxBufferLength = 4096;
    char* rawBuffer = (char*)malloc(maxBufferLength);
    if (rawBuffer == nullptr) {
        return TeepAgentComposeCborError(errorToken, TEEP_ERR_TEMPORARY_ERROR, "Out of memory", errorResponse);
    }
    encodedResponse->ptr = rawBuffer;
    encodedResponse->len = maxBufferLength;

    QCBOREncodeContext context;
    UsefulBuf buffer = UsefulBuf_Unconst(*encodedResponse);
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
            return TeepAgentComposeCborError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
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
                        return TeepAgentComposeCborError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);

                    }
                    errorToken = item.val.string;
                    QCBOREncode_AddBytesToMapN(&context, TEEP_LABEL_TOKEN, item.val.string);
                    break;
                case TEEP_LABEL_SUPPORTED_FRESHNESS_MECHANISMS:
                {
                    if (item.uDataType != QCBOR_TYPE_ARRAY) {
                        REPORT_TYPE_ERROR(errorMessage, "supported-freshness-mechanisms", QCBOR_TYPE_ARRAY, item);
                        return TeepAgentComposeCborError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                    }
                    uint16_t arrayEntryCount = item.val.uCount;
                    bool isNonceSupported = false;
                    for (uint16_t arrayIndex = 0; arrayIndex < arrayEntryCount; arrayIndex++) {
                        QCBORDecode_GetNext(decodeContext, &item);
                        if (item.uDataType != QCBOR_TYPE_INT64) {
                            REPORT_TYPE_ERROR(errorMessage, "freshness-mechanism", QCBOR_TYPE_INT64, item);
                            return TeepAgentComposeCborError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                        }
                        if (item.val.int64 == TEEP_FRESHNESS_MECHANISM_NONCE) {
                            isNonceSupported = true;
                            printf("Choosing Nonce freshness mechanism\n");
                        }
                    }
                    if (!isNonceSupported) {
                        errorMessage << "No freshness mechanism in common, TEEP Agent only supports Nonce" << std::endl;
                        return TeepAgentComposeCborError(errorToken, TEEP_ERR_UNSUPPORTED_FRESHNESS_MECHANISMS, errorMessage.str(), errorResponse);
                    }
                    break;
                }
                case TEEP_LABEL_CHALLENGE:
                    // Save challenge for use with attestation call.
                    challenge = item.val.string;
                    break;
                case TEEP_LABEL_VERSIONS:
                    printf("TODO: read versions\n");
                    // TODO(issue #70): read supported versions and potentially
                    // add selected-version to the QueryResponse.
                    break;
                }
            }

            // Parse the supported-cipher-suites.
            {
                bool found = false;
                QCBORDecode_GetNext(decodeContext, &item);
                if (item.uDataType != QCBOR_TYPE_ARRAY) {
                    REPORT_TYPE_ERROR(errorMessage, "supported-cipher-suites", QCBOR_TYPE_ARRAY, item);
                    return TeepAgentComposeCborError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                }
                uint16_t cipherSuiteCount = item.val.uCount;
                for (uint16_t cipherSuiteIndex = 0; cipherSuiteIndex < cipherSuiteCount; cipherSuiteIndex++) {
                    // Parse an array of cipher suite operations.
                    QCBORDecode_GetNext(decodeContext, &item);
                    if (item.uDataType != QCBOR_TYPE_ARRAY) {
                        REPORT_TYPE_ERROR(errorMessage, "cipher suite operations", QCBOR_TYPE_ARRAY, item);
                        return TeepAgentComposeCborError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                    }
                    uint16_t operationCount = item.val.uCount;
                    for (uint16_t operationIndex = 0; operationIndex < operationCount; operationIndex++) {
                        // Parse an array that specifies an operation.
                        QCBORDecode_GetNext(decodeContext, &item);
                        if (item.uDataType != QCBOR_TYPE_ARRAY || item.val.uCount != 2) {
                            REPORT_TYPE_ERROR(errorMessage, "cipher suite operation pair", QCBOR_TYPE_ARRAY, item);
                            return TeepAgentComposeCborError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                        }
                        QCBORDecode_GetNext(decodeContext, &item);
                        if (item.uDataType != QCBOR_TYPE_INT64) {
                            REPORT_TYPE_ERROR(errorMessage, "cose type", QCBOR_TYPE_INT64, item);
                            return TeepAgentComposeCborError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
                        }
                        int64_t coseType = item.val.int64;

                        QCBORDecode_GetNext(decodeContext, &item);
                        if (item.uDataType != QCBOR_TYPE_INT64) {
                            REPORT_TYPE_ERROR(errorMessage, "cose algorithm", QCBOR_TYPE_INT64, item);
                            return TeepAgentComposeCborError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
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
                return TeepAgentComposeCborError(errorToken, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), errorResponse);
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

    QCBORError err = QCBOREncode_Finish(&context, encodedResponse);
    return (err == QCBOR_SUCCESS) ? TEEP_ERR_SUCCESS : TEEP_ERR_TEMPORARY_ERROR;
}

teep_error_code_t TeepAgentSendCborMessage(void* sessionHandle, const char* mediaType, const char* buffer, size_t bufferlen)
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

    return TeepAgentQueueOutboundTeepMessage(sessionHandle, mediaType, buffer, bufferlen);
}

/* Compose a raw Success message to be signed. */
teep_error_code_t TeepAgentComposeCborSuccess(UsefulBufC token, UsefulBufC* encoded)
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

static teep_error_code_t TeepAgentComposeCborError(UsefulBufC token, teep_error_code_t errorCode, const std::string& errorMessage, UsefulBufC* encoded)
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
    return (err == QCBOR_SUCCESS) ? TEEP_ERR_SUCCESS : TEEP_ERR_TEMPORARY_ERROR;
}

static void TeepAgentSendError(UsefulBufC reply, void* sessionHandle)
{
    if (reply.len == 0) {
        return;
    }

    printf("Sending CBOR message: ");
    HexPrintBuffer(reply.ptr, reply.len);

    (void)TeepAgentSendCborMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, (const char*)reply.ptr, reply.len);
    free((void*)reply.ptr);
}

static teep_error_code_t TeepAgentHandleCborQueryRequest(void* sessionHandle, QCBORDecodeContext* context)
{
    printf("TeepHandleCborQueryRequest\n");

    /* 3. Compose a raw response. */
    UsefulBufC queryResponse;
    UsefulBufC errorResponse;
    teep_error_code_t errorCode = TeepAgentComposeCborQueryResponse(context, &queryResponse, &errorResponse);
    if (errorCode != TEEP_ERR_SUCCESS) {
        TeepAgentSendError(errorResponse, sessionHandle);
        return errorCode;
    }
    if (queryResponse.len == 0) {
        return TEEP_ERR_PERMANENT_ERROR;
    }

    printf("Sending CBOR message: ");
    HexPrintBuffer(queryResponse.ptr, queryResponse.len);

    printf("Sending QueryResponse...\n");

    errorCode = TeepAgentSendCborMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, (const char*)queryResponse.ptr, queryResponse.len);
    free((void*)queryResponse.ptr);
    return errorCode;
}

teep_error_code_t TeepAgentHandleCborUpdate(void* sessionHandle, QCBORDecodeContext* context)
{
    printf("TeepHandleCborUpdate\n");

    std::ostringstream errorMessage;
    QCBORItem item;
    UsefulBufC token = NULLUsefulBufC;
    teep_error_code_t teeperr = TEEP_ERR_SUCCESS;
    UsefulBufC errorResponse = NULLUsefulBufC;

    // Parse the options map.
    QCBORDecode_GetNext(context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        REPORT_TYPE_ERROR(errorMessage, "options", QCBOR_TYPE_MAP, item);
        teeperr = TeepAgentComposeCborError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
        TeepAgentSendError(errorResponse, sessionHandle);
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
                teeperr = TeepAgentComposeCborError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
                TeepAgentSendError(errorResponse, sessionHandle);
                return teeperr;
            }
            token = item.val.string;
            break;
        }
        case TEEP_LABEL_MANIFEST_LIST:
        {
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                REPORT_TYPE_ERROR(errorMessage, "manifest-list", QCBOR_TYPE_ARRAY, item);
                teeperr = TeepAgentComposeCborError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
                TeepAgentSendError(errorResponse, sessionHandle);
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
                    teeperr = TeepAgentComposeCborError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
                    TeepAgentSendError(errorResponse, sessionHandle);
                    return teeperr;
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
                teeperr = TeepAgentComposeCborError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
                TeepAgentSendError(errorResponse, sessionHandle);
                return teeperr;
            }
            // TODO: use Attestation Result.
            break;
        }
        case TEEP_LABEL_ATTESTATION_PAYLOAD:
        {
            if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                REPORT_TYPE_ERROR(errorMessage, "attestation-payload", QCBOR_TYPE_BYTE_STRING, item);
                teeperr = TeepAgentComposeCborError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
                TeepAgentSendError(errorResponse, sessionHandle);
                return teeperr;
            }
            // TODO: use Attestation Result.
            break;
        }
        default:
            errorMessage << "Unrecognized option label " << label;
            teeperr = TeepAgentComposeCborError(token, TEEP_ERR_PERMANENT_ERROR, errorMessage.str(), &errorResponse);
            TeepAgentSendError(errorResponse, sessionHandle);
            return teeperr;
        }
    }

    /* 3. Compose a Success reply. */
    UsefulBufC reply;
    teeperr = TeepAgentComposeCborSuccess(token, &reply);
    if (teeperr != TEEP_ERR_SUCCESS) {
        return teeperr;
    }
    if (reply.len == 0) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }

    printf("Sending CBOR message: ");
    HexPrintBuffer(reply.ptr, reply.len);

    teeperr = TeepAgentSendCborMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, (const char*)reply.ptr, reply.len);
    free((void*)reply.ptr);
    return teeperr;
}

/* Handle an incoming message from a TAM. */
static teep_error_code_t TeepAgentHandleCborMessage(
    _In_ void* sessionHandle,
    _In_reads_(messageLength) const char* message,
    size_t messageLength)
{
    teep_error_code_t teeperr = TEEP_ERR_SUCCESS;
    std::ostringstream errorMessage;
    QCBORDecodeContext context;
    QCBORItem item;
    UsefulBufC encoded;

    // From draft-ietf-teep-protocol section 4.1.2:
    //  1.  Verify that the received message is a valid CBOR object.

    //  2.  Verify that the message contains a COSE_Sign1 structure.
    // ... TODO(issue #8) ...
    struct t_cose_sign1_verify_ctx verify_ctx;
    t_cose_sign1_verify_init(&verify_ctx, 0);

    struct t_cose_key key_pair;
    teeperr = TeepAgentGetTamKey(&key_pair);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    //  3.  Verify that the resulting COSE Header includes only parameters
    //      and values whose syntax and semantics are both understood and
    //      supported or that are specified as being ignored when not
    //      understood.
    // ... TODO(issue #8) ...

    //  4.  Follow the steps specified in Section 4 of [RFC8152] ("Signing
    //      Objects") for validating a COSE_Sign1 object.  The COSE_Sign1
    //      payload is the content of the TEEP message.
    // ... TODO(issue #8) ...
    UsefulBufC signed_cose;
    signed_cose.ptr = message;
    signed_cose.len = messageLength;

    printf("Signed:   ");
    HexPrintBuffer(message, messageLength);
    printf("\n");

    int return_value = t_cose_sign1_verify(&verify_ctx,
        signed_cose,         /* COSE to verify */
        &encoded,            /* Payload from signed_cose */
        NULL);               /* Don't return parameters */
    if (return_value != T_COSE_SUCCESS) {
        printf("TAM key verification failed\n");
        return TEEP_ERR_PERMANENT_ERROR;
    }

    printf("Received CBOR message: ");
    HexPrintBuffer(encoded.ptr, encoded.len);

    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_ARRAY) {
        // TODO: if one cannot parse a message into a type, should one
        // send an Error message back or not?
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
        teeperr = TeepAgentHandleCborQueryRequest(sessionHandle, &context);
        break;
    case TEEP_MESSAGE_UPDATE:
        teeperr = TeepAgentHandleCborUpdate(sessionHandle, &context);
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

teep_error_code_t TeepAgentProcessTeepMessage(
    _In_ void* sessionHandle,
    _In_z_ const char* mediaType,
    _In_reads_(messageLength) const char* message,
    size_t messageLength)
{
    teep_error_code_t err = TEEP_ERR_SUCCESS;

    printf("Received contentType='%s' messageLength=%zd\n", mediaType, messageLength);

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
        printf("Sending an empty message...\n");
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
        printf("Sending an empty message...\n");
        const char* acceptMediaType = TEEP_CBOR_MEDIA_TYPE;
        teep_error = TeepAgentConnect(tamUri, acceptMediaType);
        if (teep_error != TEEP_ERR_SUCCESS) {
            return teep_error;
        }
    } else {
        // TODO: implement going on to the next message.
        TEEP_ASSERT(false);
    }

    return teep_error;
}
