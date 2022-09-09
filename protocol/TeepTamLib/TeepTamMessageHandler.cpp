// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"
#include "openssl/x509.h"
#include "openssl/evp.h"
#include "Manifest.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "TeepTamEcallHandler.h"
#include "RequestedComponentInfo.h"
#include "TeepTamLib.h"
#include <sstream>

#define TAM_SIGNING_PRIVATE_KEY_PAIR_FILENAME "./tam/tam-private-key-pair.pem"

static teep_error_code_t TamGetSigningKeyPair(struct t_cose_key* key_pair)
{
    return teep_get_signing_key_pair(key_pair, TAM_SIGNING_PRIVATE_KEY_PAIR_FILENAME, TAM_SIGNING_PUBLIC_KEY_FILENAME);
}

/* Get the TEEP Agent's public key to verify an incoming message against. */
/* TODO: support multiple TEEP Agents */
teep_error_code_t TamGetTeepAgentKey(_Out_ struct t_cose_key* key_pair)
{
    return teep_get_verifying_key_pair(key_pair, TEEP_AGENT_SIGNING_PUBLIC_KEY_FILENAME);
}

const unsigned char* g_TamDerCertificate = nullptr;
size_t g_TamDerCertificateSize = 0;

const unsigned char* GetTamDerCertificate(size_t *pCertLen)
{
    if (g_TamDerCertificate == nullptr) {
        // Construct a self-signed DER certificate based on the COSE key.
        t_cose_key key_pair;
        teep_error_code_t teep_error = TamGetSigningKeyPair(&key_pair);
        if (teep_error != TEEP_ERR_SUCCESS) {
            return nullptr;
        }

        g_TamDerCertificate = GetDerCertificate(&key_pair, &g_TamDerCertificateSize);
    }

    *pCertLen = g_TamDerCertificateSize;
    return g_TamDerCertificate;
}

/* Compose a raw QueryRequest message to be signed. */
static teep_error_code_t TamComposeCborQueryRequest(
    _Out_ UsefulBufC* bufferToSend)
{
    QCBOREncodeContext context;
    UsefulBuf buffer = UsefulBuf_Unconst(*bufferToSend);
    QCBOREncode_Init(&context, buffer);

    QCBOREncode_OpenArray(&context);
    {
        // Add TYPE.
        QCBOREncode_AddInt64(&context, TEEP_MESSAGE_QUERY_REQUEST);

        QCBOREncode_OpenMap(&context);
        {
            // Create a random token only if the attestation bit will be clear,
            // but we always set the attestation bit so we never add a token.

            // Add supported freshness mechanisms (defaults to nonce only).
            QCBOREncode_OpenArrayInMapN(&context, TEEP_LABEL_SUPPORTED_FRESHNESS_MECHANISMS);
            {
                QCBOREncode_AddInt64(&context, TEEP_FRESHNESS_MECHANISM_NONCE);
            }
            QCBOREncode_CloseArray(&context);

            // Add challenge if needed.

            // Add versions if needed.

            // Add ocsp-data if needed.
        }
        QCBOREncode_CloseMap(&context);

        // Add supported cipher suites.
        QCBOREncode_OpenArray(&context);
        {
            // Add teep-cipher-suite-sign1-es256.
            QCBOREncode_OpenArray(&context);
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

            // Add teep-cipher-suite-sign1-eddsa.
            // TODO: t_cose does not yet support eddsa.
        }
        QCBOREncode_CloseArray(&context);

        // Add data-item-requested.
        QCBOREncode_AddUInt64(&context, TEEP_ATTESTATION | TEEP_TRUSTED_COMPONENTS);
    }
    QCBOREncode_CloseArray(&context);

    QCBORError err = QCBOREncode_Finish(&context, bufferToSend);
    return (err == QCBOR_SUCCESS) ? TEEP_ERR_SUCCESS : TEEP_ERR_PERMANENT_ERROR;
}

teep_error_code_t
TamSignCborMessage(
    _In_ const UsefulBufC* unsignedMessage,
    _In_ UsefulBuf signedMessageBuffer,
    _Out_ UsefulBufC* signedMessage)
{
    struct t_cose_key key_pair;
    teep_error_code_t err = TamGetSigningKeyPair(&key_pair);
    if (err != TEEP_ERR_SUCCESS) {
        return err;
    }

    return teep_sign_cbor_message(key_pair, unsignedMessage, signedMessageBuffer, signedMessage);
}

static teep_error_code_t
TamSendCborMessage(
    _In_ void* sessionHandle,
    _In_z_ const char* mediaType,
    _In_ const UsefulBufC* unsignedMessage,
    bool signMessage)
{
    UsefulBufC signedMessage;
    const char* output_buffer;
    size_t output_buffer_length;

#ifdef TEEP_USE_COSE
    if (signMessage) {
        Q_USEFUL_BUF_MAKE_STACK_UB(signed_cose_buffer, 300);
        teep_error_code_t error = TamSignCborMessage(unsignedMessage, signed_cose_buffer, &signedMessage);
        if (error != TEEP_ERR_SUCCESS) {
            return error;
        }

        output_buffer = (const char*)signedMessage.ptr;
        output_buffer_length = signedMessage.len;
    } else {
#endif
        output_buffer = (const char*)unsignedMessage->ptr;
        output_buffer_length = unsignedMessage->len;
#ifdef TEEP_USE_COSE
    }
#endif

    return TamQueueOutboundTeepMessage(sessionHandle, mediaType, output_buffer, output_buffer_length);
}

/* Handle a new incoming connection from a device. */
static teep_error_code_t TamProcessTeepConnect(
    _In_ void* sessionHandle,
    _In_z_ const char* mediaType)
{
    printf("Received client connection\n");

    teep_error_code_t teep_error = TEEP_ERR_SUCCESS;
    Q_USEFUL_BUF_MAKE_STACK_UB(encoded, 4096);
    UsefulBufC encodedC = UsefulBuf_Const(encoded);

    teep_error = TamComposeCborQueryRequest(&encodedC);
    if (teep_error != TEEP_ERR_SUCCESS) {
        return teep_error;
    }

    if (encoded.len == 0) {
        return TEEP_ERR_PERMANENT_ERROR;
    }

    printf("Sending CBOR message: ");
    HexPrintBuffer(encodedC.ptr, encodedC.len);

    printf("Sending QueryRequest...\n");
    teep_error = TamSendCborMessage(sessionHandle, mediaType, &encodedC, false);
    return teep_error;
}

teep_error_code_t TamProcessConnect(_In_ void* sessionHandle, _In_z_ const char* acceptMediaType)
{
    if (strncmp(acceptMediaType, TEEP_CBOR_MEDIA_TYPE, strlen(TEEP_CBOR_MEDIA_TYPE)) == 0) {
        return TamProcessTeepConnect(sessionHandle, acceptMediaType);
    } else {
        return TEEP_ERR_PERMANENT_ERROR;
    }
}

/* Compose a raw Update message to be signed. */
static teep_error_code_t TamComposeCborUpdate(
    _Out_ UsefulBufC* encoded,
    _In_ const RequestedComponentInfo* currentComponentList,
    _In_ const RequestedComponentInfo* requestedComponentList,
    _In_ const RequestedComponentInfo* unneededComponentList,
    _Out_ int* count)
{
    *count = 0;
    *encoded = NULLUsefulBufC;

    int maxBufferLength = 4096;
    char* rawBuffer = (char*)malloc(maxBufferLength);
    if (rawBuffer == nullptr) {
        return TEEP_ERR_TEMPORARY_ERROR; /* Error */
    }
    encoded->ptr = rawBuffer;
    encoded->len = maxBufferLength;

    QCBOREncodeContext context;
    UsefulBuf buffer = UsefulBuf_Unconst(*encoded);
    QCBOREncode_Init(&context, buffer);

    QCBOREncode_OpenArray(&context);
    {
        // Add TYPE.
        QCBOREncode_AddInt64(&context, TEEP_MESSAGE_UPDATE);

        QCBOREncode_OpenMap(&context);
        {
            // Spec issue #166: we assume it's optional whether
            // to include a token, so we don't.
#if 0
            /* Create a random token. */
            UsefulBuf_MAKE_STACK_UB(token, 8);
            teep_error_code_t result = teep_random(token.ptr, token.len);
            if (result != TEEP_ERR_SUCCESS) {
                return result;
            }
            QCBOREncode_AddBytesToMapN(&context, TEEP_LABEL_TOKEN, UsefulBuf_Const(token));
#endif

            QCBOREncode_OpenArrayInMapN(&context, TEEP_LABEL_MANIFEST_LIST);
            {
                // Any SUIT manifest for any required components that aren't reported to be present.
                for (Manifest* manifest = Manifest::First(); manifest != nullptr; manifest = manifest->Next) {
                    bool found = false;
                    for (const RequestedComponentInfo* cci = currentComponentList; cci != nullptr; cci = cci->Next) {
                        if (manifest->HasComponentId(&cci->ComponentId)) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        QCBOREncode_AddBytes(&context, manifest->ManifestContents);
                        (*count)++;
                    }
                }

                // Add SUIT manifest for any optional components that were requested.
                for (const RequestedComponentInfo* rci = requestedComponentList; rci != nullptr; rci = rci->Next) {
                    Manifest* manifest = Manifest::FindManifest(&rci->ComponentId);
                    if ((manifest == nullptr) || (manifest->IsRequired)) {
                        continue;
                    }

                    // The component is allowed and optional, so ok to install on request.
                    QCBOREncode_AddBytes(&context, manifest->ManifestContents);
                    (*count)++;
                }

                // Add a deletion manifest for any optional components that are reported as unneeded.
                for (const RequestedComponentInfo* rci = unneededComponentList; rci != nullptr; rci = rci->Next) {
                    Manifest* manifest = Manifest::FindManifest(&rci->ComponentId);
                    if ((manifest == nullptr) || (manifest->IsRequired)) {
                        continue;
                    }

                    // The component is allowed but optional, so ok to delete on request.
                    // TODO: need a deletion manifest
#if 0
                    QCBOREncode_AddBytes(&context, manifest->DeletionManifestContents);
                    (*count)++;
#endif
                }

                // List any installed components that are not in the required or optional list.
                for (const RequestedComponentInfo* rci = currentComponentList; rci != nullptr; rci = rci->Next) {
                    Manifest* manifest = Manifest::FindManifest(&rci->ComponentId);
                    if (manifest != nullptr) {
                        continue;
                    }

                    // TODO: need a deletion manifest
#if 0
                    QCBOREncode_AddBytes(&context, manifest->DeletionManifestContents);
                    (*count)++;
#endif
                }
            }
            QCBOREncode_CloseArray(&context);
        }
        QCBOREncode_CloseMap(&context);
    }
    QCBOREncode_CloseArray(&context);

    QCBORError err = QCBOREncode_Finish(&context, encoded);
    return (err == QCBOR_SUCCESS) ? TEEP_ERR_SUCCESS : TEEP_ERR_TEMPORARY_ERROR;
}

teep_error_code_t ParseComponentId(
    QCBORDecodeContext* context,
    QCBORItem* item,
    RequestedComponentInfo** currentRci,
    std::ostringstream& errorMessage)
{
    if (item->uDataType != QCBOR_TYPE_ARRAY) {
        REPORT_TYPE_ERROR(errorMessage, "component-id", QCBOR_TYPE_ARRAY, *item);
        return TEEP_ERR_PERMANENT_ERROR;
    }

    // Get array size
    uint16_t componentIdEntryCount = item->val.uCount;
    if (componentIdEntryCount != 1) {
        // TODO: support more general component ids.
        return TEEP_ERR_PERMANENT_ERROR;
    }

    // Read bstr from component id array.
    QCBORDecode_GetNext(context, item);

    if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
        REPORT_TYPE_ERROR(errorMessage, "component-id", QCBOR_TYPE_BYTE_STRING, *item);
        return TEEP_ERR_PERMANENT_ERROR;
    }

    *currentRci = new RequestedComponentInfo(&item->val.string);
    return TEEP_ERR_SUCCESS;
}

teep_error_code_t TamHandleCborQueryResponse(
    void* sessionHandle,
    QCBORDecodeContext* context)
{
    printf("TamHandleCborQueryResponse\n");

    QCBORItem item;
    std::ostringstream errorMessage;
    std::string attestationPayloadFormat;

    // Parse the options map.
    QCBORDecode_GetNext(context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        REPORT_TYPE_ERROR(errorMessage, "options", QCBOR_TYPE_MAP, item);
        return TEEP_ERR_PERMANENT_ERROR;
    }
    RequestedComponentInfo currentComponentList(nullptr);
    RequestedComponentInfo requestedComponentList(nullptr);
    RequestedComponentInfo unneededComponentList(nullptr);
    uint16_t mapEntryCount = item.val.uCount;
    for (int mapEntryIndex = 0; mapEntryIndex < mapEntryCount; mapEntryIndex++) {
        QCBORDecode_GetNext(context, &item);
        teep_label_t label = (teep_label_t)item.label.int64;
        switch (label) {
        case TEEP_LABEL_TOKEN:
            if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                REPORT_TYPE_ERROR(errorMessage, "token", QCBOR_TYPE_BYTE_STRING, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }

            // Since we always send QueryRequest with the attestation bit set,
            // and don't include a token in the QueryRequest, we should never
            // get a token in response.  If we do, it indicates a bug in the
            // TEEP Agent that sent the QueryResponse.
            return TEEP_ERR_PERMANENT_ERROR;

        case TEEP_LABEL_SELECTED_VERSION:
            if (item.uDataType != QCBOR_TYPE_INT64) {
                REPORT_TYPE_ERROR(errorMessage, "selected-version", QCBOR_TYPE_BYTE_STRING, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            if (item.val.uint64 != 0) {
                printf("Unrecognized protocol version %lld\n", item.val.uint64);
                return TEEP_ERR_PERMANENT_ERROR; /* invalid message */
            }
            break;

        case TEEP_LABEL_SELECTED_CIPHER_SUITE: {
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                REPORT_TYPE_ERROR(errorMessage, "selected-cipher-suite", QCBOR_TYPE_BYTE_STRING, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            // Parse an array of cipher suite operations.
            uint16_t operationCount = item.val.uCount;
            if (operationCount != 1) {
                return TEEP_ERR_PERMANENT_ERROR;
            }

            // Parse an array that specifies an operation.
            QCBORDecode_GetNext(context, &item);
            if (item.uDataType != QCBOR_TYPE_ARRAY || item.val.uCount != 2) {
                REPORT_TYPE_ERROR(errorMessage, "cipher suite operation pair", QCBOR_TYPE_ARRAY, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            QCBORDecode_GetNext(context, &item);
            if (item.uDataType != QCBOR_TYPE_INT64) {
                REPORT_TYPE_ERROR(errorMessage, "cose type", QCBOR_TYPE_INT64, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            if (item.val.int64 != CBOR_TAG_COSE_SIGN1) {
                printf("Unrecognized COSE type %lld\n", item.val.uint64);
                return TEEP_ERR_PERMANENT_ERROR; /* invalid cipher suite */
            }
            QCBORDecode_GetNext(context, &item);
            if (item.uDataType != QCBOR_TYPE_INT64) {
                REPORT_TYPE_ERROR(errorMessage, "cose algorithm", QCBOR_TYPE_INT64, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            if (item.val.int64 != T_COSE_ALGORITHM_ES256) {
                printf("Unrecognized COSE algorithm %lld\n", item.val.uint64);
                return TEEP_ERR_PERMANENT_ERROR; /* invalid cipher suite */
            }
            break;
        }

        case TEEP_LABEL_REQUESTED_TC_LIST:
        {
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                REPORT_TYPE_ERROR(errorMessage, "requested-tc-list", QCBOR_TYPE_ARRAY, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            uint16_t arrayEntryCount = item.val.uCount;
            for (int arrayEntryIndex = 0; arrayEntryIndex < arrayEntryCount; arrayEntryIndex++) {
                QCBORDecode_GetNext(context, &item);
                if (item.uDataType != QCBOR_TYPE_MAP) {
                    REPORT_TYPE_ERROR(errorMessage, "requested-tc-info", QCBOR_TYPE_MAP, item);
                    return TEEP_ERR_PERMANENT_ERROR;
                }
                uint16_t tcInfoParameterCount = item.val.uCount;
                RequestedComponentInfo* currentRci = nullptr;
                for (int tcInfoParameterIndex = 0; tcInfoParameterIndex < tcInfoParameterCount; tcInfoParameterIndex++) {
                    QCBORDecode_GetNext(context, &item);
                    teep_label_t label = (teep_label_t)item.label.int64;
                    switch (label) {
                    case TEEP_LABEL_COMPONENT_ID:
                    {
                        if (currentRci != nullptr) {
                            // Duplicate.
                            return TEEP_ERR_PERMANENT_ERROR;
                        }
                        teep_error_code_t errorCode = ParseComponentId(context, &item, &currentRci, errorMessage);
                        if (errorCode != TEEP_ERR_SUCCESS) {
                            return errorCode;
                        }
                        currentRci->Next = requestedComponentList.Next;
                        requestedComponentList.Next = currentRci;
                        break;
                    }
                    case TEEP_LABEL_TC_MANIFEST_SEQUENCE_NUMBER:
                        if (item.uDataType != QCBOR_TYPE_UINT64) {
                            REPORT_TYPE_ERROR(errorMessage, "tc-manifest-sequence-number", QCBOR_TYPE_UINT64, item);
                            return TEEP_ERR_PERMANENT_ERROR;
                        }
                        if (currentRci == nullptr) {
                            return TEEP_ERR_PERMANENT_ERROR;
                        }
                        currentRci->ManifestSequenceNumber = item.val.uint64;
                        break;
                    case TEEP_LABEL_HAVE_BINARY:
                        if (item.uDataType != QCBOR_TYPE_UINT64) {
                            REPORT_TYPE_ERROR(errorMessage, "have-binary", QCBOR_TYPE_UINT64, item);
                            return TEEP_ERR_PERMANENT_ERROR;
                        }
                        if (currentRci == nullptr) {
                            return TEEP_ERR_PERMANENT_ERROR;
                        }
                        currentRci->HaveBinary = (item.val.uint64 != 0);
                        break;
                    default:
                        printf("Unrecognized option label %d\n", label);
                        return TEEP_ERR_PERMANENT_ERROR; /* invalid message */
                    }
                }
            }
            break;
        }
        case TEEP_LABEL_UNNEEDED_TC_LIST:
        {
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                REPORT_TYPE_ERROR(errorMessage, "unneeded-tc-list", QCBOR_TYPE_ARRAY, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            uint16_t arrayEntryCount = item.val.uCount;
            for (int arrayEntryIndex = 0; arrayEntryIndex < arrayEntryCount; arrayEntryIndex++) {
                QCBORDecode_GetNext(context, &item);

                RequestedComponentInfo* currentUci = nullptr;
                teep_error_code_t errorCode = ParseComponentId(context, &item, &currentUci, errorMessage);
                if (errorCode != TEEP_ERR_SUCCESS) {
                    return errorCode;
                }
                currentUci->Next = unneededComponentList.Next;
                unneededComponentList.Next = currentUci;
            }
            break;
        }
        case TEEP_LABEL_TC_LIST:
        {
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                REPORT_TYPE_ERROR(errorMessage, "tc-list", QCBOR_TYPE_ARRAY, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            RequestedComponentInfo* currentRci = nullptr;
            uint16_t arrayEntryCount = item.val.uCount;
            for (int arrayEntryIndex = 0; arrayEntryIndex < arrayEntryCount; arrayEntryIndex++) {
                QCBORDecode_GetNext(context, &item);
                if (item.uDataType != QCBOR_TYPE_MAP) {
                    REPORT_TYPE_ERROR(errorMessage, "tc-list", QCBOR_TYPE_MAP, item);
                    return TEEP_ERR_PERMANENT_ERROR;
                }
                uint16_t tcInfoParameterCount = item.val.uCount;
                for (int tcInfoParameterIndex = 0; tcInfoParameterIndex < tcInfoParameterCount; tcInfoParameterIndex++) {
                    QCBORDecode_GetNext(context, &item);
                    teep_label_t label = (teep_label_t)item.label.int64;
                    switch (label) {
                    case TEEP_LABEL_COMPONENT_ID:
                    {
                        if (currentRci != nullptr) {
                            // Duplicate.
                            return TEEP_ERR_PERMANENT_ERROR;
                        }
                        teep_error_code_t errorCode = ParseComponentId(context, &item, &currentRci, errorMessage);
                        if (errorCode != TEEP_ERR_SUCCESS) {
                            return errorCode;
                        }
                        currentRci->Next = currentComponentList.Next;
                        currentComponentList.Next = currentRci;
                        break;
                    }
                    case TEEP_LABEL_TC_MANIFEST_SEQUENCE_NUMBER:
                        if (item.uDataType != QCBOR_TYPE_UINT64) {
                            REPORT_TYPE_ERROR(errorMessage, "tc-manifest-sequence-number", QCBOR_TYPE_UINT64, item);
                            return TEEP_ERR_PERMANENT_ERROR;
                        }
                        if (currentRci == nullptr) {
                            return TEEP_ERR_PERMANENT_ERROR;
                        }
                        currentRci->ManifestSequenceNumber = item.val.uint64;
                        break;
                    default:
#ifdef _DEBUG
                        printf("Unrecognized option label %d\n", label);
#endif
                        return TEEP_ERR_PERMANENT_ERROR; /* invalid message */
                    }
                }
            }
            break;
        }
        case TEEP_LABEL_ATTESTATION_PAYLOAD_FORMAT: {
            if (item.uDataType != QCBOR_TYPE_TEXT_STRING) {
                REPORT_TYPE_ERROR(errorMessage, "attestation-payload-format", QCBOR_TYPE_ARRAY, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            attestationPayloadFormat = std::string((const char*)item.val.string.ptr, item.val.string.len);
            break;
        }
        case TEEP_LABEL_ATTESTATION_PAYLOAD:
            if (attestationPayloadFormat == "application/eat-cwt; profile=https://datatracker.ietf.org/doc/html/draft-ietf-teep-protocol-09") {
                // We have Attestation Results.
#ifdef _DEBUG
                printf("Got attestation results in the TEEP profile\n");
#endif
            } else {
                // We have Evidence that we need to send to a verifier.
#ifdef _DEBUG
                printf("Got Evidence in format: %s\n", attestationPayloadFormat.c_str());
#endif
            }
            break;
        default:
#ifdef _DEBUG
            printf("Unrecognized option label %d\n", label);
#endif
            return TEEP_ERR_PERMANENT_ERROR; /* invalid message */
        }
    }

    if (requestedComponentList.Next != nullptr) {
        // 3. Compose an Update message.
        UsefulBufC update;
        int count;
        teep_error_code_t err = TamComposeCborUpdate(&update, currentComponentList.Next, requestedComponentList.Next, unneededComponentList.Next, &count);
        if (err != 0) {
            return err;
        }
        if (count > 0) {
            if (update.len == 0) {
                return TEEP_ERR_TEMPORARY_ERROR;
            }

            printf("Sending CBOR message: ");
            HexPrintBuffer(update.ptr, update.len);

            printf("Sending Update message...\n");

            err = TamSendCborMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, &update, true);
            free((void*)update.ptr);
            if (err != TEEP_ERR_SUCCESS) {
                return err;
            }
        }
    }

    return TEEP_ERR_SUCCESS;
}

teep_error_code_t TamHandleCborSuccess(void* sessionHandle, QCBORDecodeContext* context)
{
    (void)sessionHandle;
    (void)context;

    printf("Received Success message...\n");

    QCBORItem item;
    std::ostringstream errorMessage;

    // Parse the options map.
    QCBORDecode_GetNext(context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        REPORT_TYPE_ERROR(errorMessage, "options", QCBOR_TYPE_MAP, item);
        return TEEP_ERR_PERMANENT_ERROR;
    }

    uint16_t mapEntryCount = item.val.uCount;
    for (int mapEntryIndex = 0; mapEntryIndex < mapEntryCount; mapEntryIndex++) {
        QCBORDecode_GetNext(context, &item);
        teep_label_t label = (teep_label_t)item.label.int64;
        switch (label) {
        case TEEP_LABEL_TOKEN:
            if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                REPORT_TYPE_ERROR(errorMessage, "token", QCBOR_TYPE_BYTE_STRING, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }

            // Since we never send a token in an Update message, we should never
            // get a token in response.  If we do, it indicates a bug in the
            // TEEP Agent that sent the Success message.
            return TEEP_ERR_PERMANENT_ERROR;

        case TEEP_LABEL_MSG: {
            if (item.uDataType != QCBOR_TYPE_TEXT_STRING) {
                printf("Wrong msg data type %d\n", item.uDataType);
                return TEEP_ERR_PERMANENT_ERROR; /* invalid message */
            }
            printf("MSG: %hs\n", std::string((const char*)item.val.string.ptr, item.val.string.len).c_str());
            break;
        }

        case TEEP_LABEL_SUIT_REPORTS:
        {
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                REPORT_TYPE_ERROR(errorMessage, "suit-reports", QCBOR_TYPE_ARRAY, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }

            uint16_t arrayEntryCount = item.val.uCount;
            for (int arrayEntryIndex = 0; arrayEntryIndex < arrayEntryCount; arrayEntryIndex++) {
                QCBORDecode_GetNext(context, &item);
                if (item.uDataType != QCBOR_TYPE_MAP) {
                    REPORT_TYPE_ERROR(errorMessage, "suit-report", QCBOR_TYPE_MAP, item);
                    return TEEP_ERR_PERMANENT_ERROR;
                }
            }
            break;
        }
        default:
#ifdef _DEBUG
            printf("Unrecognized option label %d\n", label);
#endif
            return TEEP_ERR_PERMANENT_ERROR; /* invalid message */
        }
    }

    return TEEP_ERR_SUCCESS;
}

teep_error_code_t TamHandleCborError(
    void* sessionHandle,
    QCBORDecodeContext* context)
{
    (void)sessionHandle;
    (void)context;

    printf("Received Error message...\n");
    return TEEP_ERR_SUCCESS;
}

/* Handle an incoming message from a TEEP Agent. */
teep_error_code_t TamHandleCborMessage(
    _In_ void* sessionHandle,
    _In_reads_(messageLength) const char* message,
    size_t messageLength)
{
    printf("TeepHandleCborMessage got COSE message:\n");
    HexPrintBuffer(message, messageLength);
    printf("\n");

    teep_error_code_t teeperr = TEEP_ERR_SUCCESS;
    struct t_cose_key key_pair;
    teeperr = TamGetTeepAgentKey(&key_pair);
    if (teeperr != TEEP_ERR_SUCCESS) {
        return teeperr;
    }

    std::ostringstream errorMessage;
    QCBORDecodeContext context;
    QCBORItem item;
    UsefulBufC encoded;
    UsefulBufC signed_cose;
    signed_cose.ptr = message;
    signed_cose.len = messageLength;
    teeperr = teep_verify_cbor_message(&key_pair, &signed_cose, &encoded);
    if (teeperr != TEEP_ERR_SUCCESS) {
        return teeperr;
    }

    printf("Received CBOR message: ");
    HexPrintBuffer(encoded.ptr, encoded.len);

    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_ARRAY) {
        REPORT_TYPE_ERROR(errorMessage, "TYPE", QCBOR_TYPE_ARRAY, item);
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
    case TEEP_MESSAGE_QUERY_RESPONSE:
        teeperr = TamHandleCborQueryResponse(sessionHandle, &context);
        break;
    case TEEP_MESSAGE_SUCCESS:
        teeperr = TamHandleCborSuccess(sessionHandle, &context);
        break;
    case TEEP_MESSAGE_ERROR:
        teeperr = TamHandleCborError(sessionHandle, &context);
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

teep_error_code_t TamProcessTeepMessage(
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
        err = TamHandleCborMessage(sessionHandle, message, messageLength);
    } else {
        return TEEP_ERR_PERMANENT_ERROR;
    }

    return err;
}
