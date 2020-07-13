/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include "TeepTam_t.h"

#include <stdio.h>
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

/* Compose a JSON Query Request message to be signed. */
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

    /* Convert to message buffer. */
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

        /* Create a random 16-byte token. */
        unsigned char token[UNIQUE_ID_LEN];
        oe_result_t result = oe_random(token, sizeof(token));
        if (result != OE_OK) {
            return result;
        }
        QCBOREncode_AddBytes(&context, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(token));

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
    /* Compose a raw QueryRequest message to be signed. */
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
        unsigned char token[UNIQUE_ID_LEN];
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

                // TODO: get the actual manifest.  Currently this is just random bytes.
                unsigned char manifest[16];
                oe_result_t result = oe_random(manifest, sizeof(manifest));
                if (result != OE_OK) {
                    return result;
                }

                UsefulBufC buffer;
                buffer.len = sizeof(manifest);
                buffer.ptr = manifest;
                QCBOREncode_AddBytes(&context, buffer);
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

    /* 2.  Validate that certificate is chained to a trusted
     *     CA that the TAM embeds as its trust anchor.
     */
     /* ... TODO ... */

    QCBORItem item;
    QCBORDecode_GetNext(context, &item);
    if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        printf("Invalid token type %d\n", item.uDataType);
        return 1; /* invalid message */
    }
    /* TODO: Validate the token. */

    // Parse the options map.
    QCBORDecode_GetNext(context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        printf("Invalid options type %d\n", item.uDataType);
        return 1; /* invalid message */
    }

    /* 3. Compose a TrustedAppInstall. */
    UsefulBufC install;
    int err = TeepComposeCborTrustedAppInstall(&install);
    if (err != 0) {
        return err;
    }
    if (install.len == 0) {
        return 1; /* Error */
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
    case TEEP_QUERY_RESPONSE:
        if (TeepHandleCborQueryResponse(sessionHandle, &context) != 0) {
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
