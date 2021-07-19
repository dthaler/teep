// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <openenclave/enclave.h>
#include "TeepTam_t.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "../TeepCommonTALib/common.h"
extern "C" {
#include "../TeepCommonTALib/otrp.h"
#include "../TeepCommonTALib/teep_protocol.h"
};
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"
#include "openssl/x509.h"
#include "openssl/evp.h"
#include "Manifest.h"
#include "TeepTamEcallHandler.h"
#include "RequestedComponentInfo.h"
#include <sstream>

const unsigned char* g_TamDerCertificate = nullptr;
size_t g_TamDerCertificateSize = 0;

const unsigned char* GetTamDerCertificate(size_t *pCertLen)
{
    if (g_TamDerCertificate == nullptr) {
        // Construct a self-signed DER certificate based on the JWK.

        // First get the RSA key.
#ifdef TEEP_ENABLE_JSON
        json_t* jwk = GetTamEncryptionKey();
        g_TamDerCertificate = GetDerCertificate(jwk, &g_TamDerCertificateSize);
#else
        // TODO
        return nullptr;
#endif
    }

    *pCertLen = g_TamDerCertificateSize;
    return g_TamDerCertificate;
}

/* Compose a raw QueryRequest message to be signed. */
int TeepComposeCborQueryRequest(UsefulBufC* bufferToSend)
{
    QCBOREncodeContext context;
    UsefulBuf buffer = UsefulBuf_Unconst(*bufferToSend);
    QCBOREncode_Init(&context, buffer);

    QCBOREncode_OpenArray(&context);
    {
        // Add TYPE.
        QCBOREncode_AddInt64(&context, TEEP_MESSAGE_QUERY_REQUEST);

        // Create a random 64-bit token.
        uint64_t token;
        oe_result_t result = oe_random(&token, sizeof(token));
        if (result != OE_OK) {
            return result;
        }

        // Draft -03 implies we have to store the token for validation
        // upon receiving a QueryResponse, but that adversely affects
        // scalability, opens the protocol to DOS attacks similar to SYN attacks,
        // and forces the extra round trip.  See
        // https://github.com/ietf-teep/teep-protocol/issues/40 for discussion.
        // As such, we currently don't implement such a check in the hopes
        // that the draft will remove the check in the future.  But we have
        // to include a token anyway for interoperability.

        QCBOREncode_OpenMap(&context);
        {
            QCBOREncode_AddUInt64ToMapN(&context, TEEP_LABEL_TOKEN, token);
        }
        QCBOREncode_CloseMap(&context);

        // Add data-item-requested.
        QCBOREncode_AddUInt64(&context, TEEP_ATTESTATION | TEEP_TRUSTED_COMPONENTS);
    }
    QCBOREncode_CloseArray(&context);

    QCBORError err = QCBOREncode_Finish(&context, bufferToSend);
    return err;
}

teep_error_code_t TeepSendCborMessage(void* sessionHandle, const char* mediaType, const char* buffer, size_t bufferlen)
{
    // From draft-ietf-teep-protocol section 4.1.1:
    // 1.  Create a TEEP message according to the description below and
    //     populate it with the respective content.  (done by caller)
    // 2.  Create a COSE Header containing the desired set of Header
    //     Parameters.  The COSE Header MUST be valid per the [RFC8152]
    //     specification.
    // ... TODO ...

    // 3.  Create a COSE_Sign1 object using the TEEP message as the
    //     COSE_Sign1 Payload; all steps specified in [RFC8152] for creating
    //     a COSE_Sign1 object MUST be followed.
    // ... TODO ...

    // 4.  Prepend the COSE object with the TEEP CBOR tag to indicate that
    //     the CBOR-encoded message is indeed a TEEP message.
    // ... TODO ...

    int err = 0;
    oe_result_t result = ocall_QueueOutboundTeepMessage(&err, sessionHandle, mediaType, buffer, bufferlen);
    if (result != OE_OK) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }

    return TEEP_ERR_SUCCESS;
}

/* Handle a new incoming connection from a device. */
int TeepProcessConnect(void* sessionHandle, const char* mediaType)
{
    printf("Received client connection\n");

    int err = 0;
    UsefulBufC encoded;
#ifdef TEEP_ENABLE_JSON
    if (strcmp(mediaType, TEEP_JSON_MEDIA_TYPE) == 0) {
        const char* message = TeepComposeJsonQueryRequest();
        if (message == nullptr) {
            return 1; /* Error */
        }
        encoded.ptr = message;
        encoded.len = strlen(message);
    } else
#endif
    {
        int maxBufferLength = 4096;
        char* buffer = (char*)malloc(maxBufferLength);
        if (buffer == nullptr) {
            return 1; /* Error */
        }
        encoded.ptr = buffer;
        encoded.len = maxBufferLength;

        err = TeepComposeCborQueryRequest(&encoded);
        if (err != 0) {
            return err;
        }

        if (encoded.len == 0) {
            return 1; /* Error */
        }

        printf("Sending CBOR message: ");
        HexPrintBuffer(encoded.ptr, encoded.len);
    }

    printf("Sending QueryRequest...\n");
    err = TeepSendCborMessage(sessionHandle, mediaType, (const char*)encoded.ptr, encoded.len);
    free((void*)encoded.ptr);
    return err;
}

int ecall_ProcessTeepConnect(void* sessionHandle, const char* acceptMediaType)
{
#ifdef ENABLE_OTRP
    if (strncmp(acceptMediaType, OTRP_JSON_MEDIA_TYPE, strlen(OTRP_JSON_MEDIA_TYPE)) == 0) {
        return OTrPProcessConnect(sessionHandle);
    } else
#endif
    if ((strncmp(acceptMediaType, TEEP_CBOR_MEDIA_TYPE, strlen(TEEP_CBOR_MEDIA_TYPE)) == 0)
#ifdef TEEP_ENABLE_JSON
            || (strncmp(acceptMediaType, TEEP_JSON_MEDIA_TYPE, strlen(TEEP_JSON_MEDIA_TYPE)) == 0)
#endif
        ) {
        return TeepProcessConnect(sessionHandle, acceptMediaType);
    } else {
        return 1;
    }
}

/* Compose a raw Update message to be signed. */
teep_error_code_t TeepComposeCborUpdate(
    UsefulBufC* encoded,
    RequestedComponentInfo* currentComponentList,
    RequestedComponentInfo* requestedComponentList,
    RequestedComponentInfo* unneededComponentList,
    int* count)
{
    *count = 0;
    encoded->ptr = nullptr;
    encoded->len = 0;

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

        /* Create a random 64-bit token. */
        uint64_t token;
        oe_result_t result = oe_random(&token, sizeof(token));
        if (result != OE_OK) {
            return TEEP_ERR_TEMPORARY_ERROR;
        }

        QCBOREncode_OpenMap(&context);
        {
            QCBOREncode_AddUInt64ToMapN(&context, TEEP_LABEL_TOKEN, token);

            QCBOREncode_OpenArrayInMapN(&context, TEEP_LABEL_TC_LIST);
            {
                // List any optional components that are reported as unneeded.
                for (RequestedComponentInfo* rci = unneededComponentList; rci != nullptr; rci = rci->Next) {
                    Manifest* manifest = Manifest::FindManifest(&rci->ComponentId);
                    if ((manifest == nullptr) || (manifest->IsRequired)) {
                        continue;
                    }

                    // The component is allowed but optional, so ok to delete on request.
                    QCBOREncode_AddBytes(&context, rci->ComponentId);
                    (*count)++;
                }

                // List any installed components that are not in the required or optional list.
                for (RequestedComponentInfo* rci = currentComponentList; rci != nullptr; rci = rci->Next) {
                    Manifest* manifest = Manifest::FindManifest(&rci->ComponentId);
                    if (manifest != nullptr) {
                        continue;
                    }

                    // The installed component is not found in the latest policy.
                    QCBOREncode_AddBytes(&context, rci->ComponentId);
                    (*count)++;
                }
            }
            QCBOREncode_CloseArray(&context);

            QCBOREncode_OpenArrayInMapN(&context, TEEP_LABEL_MANIFEST_LIST);
            {
                // Any SUIT manifest for any required components that aren't reported to be present.
                for (Manifest* manifest = Manifest::First(); manifest != nullptr; manifest = manifest->Next) {
                    bool found = false;
                    for (RequestedComponentInfo* cci = currentComponentList; cci != nullptr; cci = cci->Next) {
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
                for (RequestedComponentInfo* rci = requestedComponentList; rci != nullptr; rci = rci->Next) {
                    Manifest* manifest = Manifest::FindManifest(&rci->ComponentId);
                    if ((manifest == nullptr) || (manifest->IsRequired)) {
                        continue;
                    }

                    // The component is allowed and optional, so ok to install on request.
                    QCBOREncode_AddBytes(&context, manifest->ManifestContents);
                    (*count)++;
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

teep_error_code_t ParseComponentId(QCBORDecodeContext* context, QCBORItem* item, RequestedComponentInfo** currentRci, std::ostringstream& errorMessage)
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

teep_error_code_t TeepHandleCborQueryResponse(void* sessionHandle, QCBORDecodeContext* context)
{
    (void)sessionHandle;
    (void)context;

    printf("TeepHandleCborQueryResponse\n");

    QCBORItem item;
    std::ostringstream errorMessage;

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
            if (item.uDataType != QCBOR_TYPE_UINT64 && item.uDataType != QCBOR_TYPE_INT64) {
                REPORT_TYPE_ERROR(errorMessage, "options", QCBOR_TYPE_UINT64, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }

            /* As discussed above in comments in TeepComposeCborQueryRequest(),
             * draft -03 requires us to validate that the token matches what was
             * sent in the QueryRequest, but that causes performance problems
             * and opens us to certain DOS attacks, without any obvious
             * benefit. As such, we skip this check in the hopes that the spec
             * will be updated to
             * remove the check.
             */
            break;
        case TEEP_LABEL_SELECTED_VERSION:
            if (item.val.uint64 != 0) {
                printf("Unrecognized protocol version %lld\n", item.val.uint64);
                return TEEP_ERR_PERMANENT_ERROR; /* invalid message */
            }
            break;
        case TEEP_LABEL_SELECTED_CIPHER_SUITE:
            if ((item.val.uint64 != TEEP_CIPHERSUITE_ES256) &&
                (item.val.uint64 != TEEP_CIPHERSUITE_EDDSA)) {
                printf("Unrecognized cipher suite %lld\n", item.val.uint64);
                return TEEP_ERR_PERMANENT_ERROR; /* invalid ciphersuite */
            }
            break;
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
        case TEEP_LABEL_EVIDENCE_FORMAT:
        case TEEP_LABEL_EVIDENCE:
#ifdef _DEBUG
            printf("Ignoring unimplemented option label %d\n", label);
#endif
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
        teep_error_code_t err = TeepComposeCborUpdate(&update, currentComponentList.Next, requestedComponentList.Next, unneededComponentList.Next, &count);
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

            err = TeepSendCborMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, (const char*)update.ptr, update.len);
            free((void*)update.ptr);
            if (err != TEEP_ERR_SUCCESS) {
                return err;
            }
        }
    }

    return TEEP_ERR_SUCCESS;
}

/* Handle an incoming message from a TEEP Agent. */
teep_error_code_t TeepHandleCborMessage(void* sessionHandle, const char* message, unsigned int messageLength)
{
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
    // ... TODO ...

    //  3.  Verify that the message contains a COSE_Sign1 structure.
    // ... TODO ...

    //  4.  Verify that the resulting COSE Header includes only parameters
    //      and values whose syntax and semantics are both understood and
    //      supported or that are specified as being ignored when not
    //      understood.
    // ... TODO ...

    //  5.  Follow the steps specified in Section 4 of [RFC8152] ("Signing
    //      Objects") for validating a COSE_Sign1 object.  The COSE_Sign1
    //      payload is the content of the TEEP message.
    // ... TODO ...

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
    teep_error_code_t teeperr = TEEP_ERR_SUCCESS;
    switch (messageType) {
    case TEEP_MESSAGE_QUERY_RESPONSE:
        teeperr = TeepHandleCborQueryResponse(sessionHandle, &context);
        break;
    case TEEP_MESSAGE_SUCCESS: /* TODO */
    case TEEP_MESSAGE_ERROR: /* TODO */
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
