/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include "TeepTam_t.h"
#include "Manifest.h"

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
#include "../TeepCommonTALib/common.h"
#include "../TeepCommonTALib/otrp.h"
#include "../TeepCommonTALib/teep_protocol.h"
};
#include "../jansson/JsonAuto.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"
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

// Compose a JSON Query Request message to be signed.
const char* TeepComposeJsonQueryRequestTBS(void)
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

    // Convert to message buffer.
    const char* message = json_dumps(request, 0);
    return message;
}

int TeepComposeCborQueryRequestTBS(UsefulBufC* encoded)
{
    QCBOREncodeContext context;
    UsefulBuf buffer = UsefulBuf_Unconst(*encoded);
    QCBOREncode_Init(&context, buffer);

    QCBOREncode_OpenArray(&context);
    {
        // Add TYPE.
        QCBOREncode_AddInt64(&context, TEEP_QUERY_REQUEST);

        // Create a random 16-byte token.
        unsigned char token[UUID_LENGTH];
        oe_result_t result = oe_random(token, sizeof(token));
        if (result != OE_OK) {
            return result;
        }
        QCBOREncode_AddBytes(&context, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(token));

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
            // Insert optional items here once labels are defined.
        }
        QCBOREncode_CloseMap(&context);

        QCBOREncode_AddInt64(&context, TEEP_TRUSTED_APPS);
    }
    QCBOREncode_CloseArray(&context);

    QCBORError err = QCBOREncode_Finish(&context, encoded);
    return err;
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

int TeepComposeCborQueryRequest(UsefulBufC* bufferToSend)
{
    /* Compose a raw QueryRequest message to be signed. */
    return TeepComposeCborQueryRequestTBS(bufferToSend);
}

/* Handle a new incoming connection from a device. */
int TeepProcessConnect(void* sessionHandle, const char* mediaType)
{
    printf("Received client connection\n");

    int err = 0;
    UsefulBufC encoded;
    if (strcmp(mediaType, TEEP_JSON_MEDIA_TYPE) == 0) {
        const char* message = TeepComposeJsonQueryRequest();
        if (message == nullptr) {
            return 1; /* Error */
        }
        encoded.ptr = message;
        encoded.len = strlen(message);
    } else {
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

    oe_result_t result = ocall_QueueOutboundTeepMessage(&err, sessionHandle, mediaType, (const char*)encoded.ptr, encoded.len);
    free((void*)encoded.ptr);
    if (result != OE_OK) {
        return result;
    }

    return err;
}

int ecall_ProcessTeepConnect(void* sessionHandle, const char* acceptMediaType)
{
    if (strncmp(acceptMediaType, OTRP_JSON_MEDIA_TYPE, strlen(OTRP_JSON_MEDIA_TYPE)) == 0) {
        return OTrPProcessConnect(sessionHandle);
    } else if (strncmp(acceptMediaType, TEEP_CBOR_MEDIA_TYPE, strlen(TEEP_CBOR_MEDIA_TYPE)) == 0 ||
               strncmp(acceptMediaType, TEEP_JSON_MEDIA_TYPE, strlen(TEEP_JSON_MEDIA_TYPE)) == 0) {
        return TeepProcessConnect(sessionHandle, acceptMediaType);
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
    (void)sessionHandle; // Unused.
    (void)message; // Unused.
    (void)messageLength; // Unused.

    /* Unrecognized message. */
    return 1;
}

// Returns 0 on success, non-zero on error.
int TeepComposeCborTrustedAppInstallTBS(UsefulBufC* encoded)
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
        QCBOREncode_AddInt64(&context, TEEP_TRUSTED_APP_INSTALL);

        /* Create a random 16-byte token. */
        unsigned char token[UUID_LENGTH];
        oe_result_t result = oe_random(token, sizeof(token));
        if (result != OE_OK) {
            return result;
        }
        QCBOREncode_AddBytes(&context, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(token));

        QCBOREncode_OpenMap(&context);
        {
            QCBOREncode_OpenArrayInMapN(&context, TEEP_LABEL_MANIFEST_LIST);
            {
                // Add SUIT manifest for any requested TA(s) that we decide to install.
                // TODO: make a decision whether to install it or not.  For now, we go ahead.

                const char* taid = "ta1"; // TODO get the actual TA ID

                UsefulBufC manifest;
                manifest.ptr = Manifest::GetManifest(taid, &manifest.len);
                QCBOREncode_AddEncoded(&context, manifest);
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
int TeepComposeCborTrustedAppInstall(UsefulBufC* install)
{
    /* Compose a raw TrustedAppInstall message to be signed. */
    return TeepComposeCborTrustedAppInstallTBS(install);
}

// Returns 0 on success, non-zero on error.
int TeepHandleCborQueryResponse(void* sessionHandle, QCBORDecodeContext* context)
{
    (void)sessionHandle;
    (void)context;

    printf("TeepHandleCborQueryResponse\n");

    /* 1.  Validate COSE message signing.  If it doesn't pass, an error message is returned. */
    /* ... TODO ... */

    /* 2.  Validate that the certificate is chained to a trusted
     *     CA that the TAM embeds as its trust anchor.
     */
    /* ... TODO ... */

    QCBORItem item;
    QCBORDecode_GetNext(context, &item);
    if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        printf("Invalid token type %d\n", item.uDataType);
        return 1; // Invalid message.
    }

    /* As discussed above in comments in TeepComposeCborQueryRequestTBS(),
     * draft -03 requires us to validate that the token matches what was
     * sent in the QueryRequest, but that causes performance problems and
     * opens us to certain DOS attacks, without any obvious benefit. As such,
     * we skip this check in the hopes that the spec will be updated to
     * remove the check.
     */

    // Parse the options map.
    QCBORDecode_GetNext(context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        printf("Invalid options type %d\n", item.uDataType);
        return 1; // Invalid message.
    }

    // 3. Compose a TrustedAppInstall.
    UsefulBufC install;
    int err = TeepComposeCborTrustedAppInstall(&install);
    if (err != 0) {
        return err;
    }
    if (install.len == 0) {
        return 1; // Error.
    }

    printf("Sending CBOR message: ");
    HexPrintBuffer(install.ptr, install.len);

    printf("Sending TrustedAppInstall...\n");

    oe_result_t result = ocall_QueueOutboundTeepMessage(&err, sessionHandle, TEEP_CBOR_MEDIA_TYPE, (const char*)install.ptr, install.len);
    free((void*)install.ptr);
    if (result != OE_OK) {
        return result;
    }

    return err;
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
        return 1; // Invalid message.
    }

    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_INT64) {
        printf("Invalid TYPE type %d\n", item.uDataType);
        return 1; // Invalid message.
    }

    teep_message_type_t messageType = (teep_message_type_t)item.val.uint64;
    printf("Received CBOR TEEP message type=%d\n", messageType);
    switch (messageType) {
    case TEEP_QUERY_RESPONSE:
        if (TeepHandleCborQueryResponse(sessionHandle, &context) != 0) {
            return 1;
        }
        break;
    default:
        return 1; // Unknown message type.
        break;
    }

    QCBORError err = QCBORDecode_Finish(&context);
    return err;
}
