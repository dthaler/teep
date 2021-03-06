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
#include "q_useful_buf.h"
#include "t_cose_common.h"
#include "t_cose_sign1_sign.h"
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

        QCBOREncode_OpenMap(&context);
        {
            // Create a random token only if the attestation bit will be clear,
            // but we always set the attestation bit so we never add a token.

            // Add supported cipher suites (defaults to both).

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

        // Add data-item-requested.
        QCBOREncode_AddUInt64(&context, TEEP_ATTESTATION | TEEP_TRUSTED_COMPONENTS);
    }
    QCBOREncode_CloseArray(&context);

    QCBORError err = QCBOREncode_Finish(&context, bufferToSend);
    return err;
}

#ifdef TEEP_USE_COSE
// Some temporarily hard coded keys.
// TODO: remove hard coded keys.
#define PUBLIC_KEY_prime256v1 \
"0437ab65955fae0466673c3a2934a3" \
"4f2f0ec2b3eec224198557998fc04b" \
"f4b2b495d9798f2539c90d7d102b3b" \
"bbda7fcbdb0e9b58d4e1ad2e61508d" \
"a75f84a67b"

#define PRIVATE_KEY_prime256v1 \
"f1b7142343402f3b5de7315ea894f9" \
"da5cf503ff7938a37ca14eb0328698" \
"8450"

/**
 * \brief Make an EC key pair in OpenSSL library form.
 *
 * \param[in] cose_algorithm_id  The algorithm to sign with, for example
 *                               \ref T_COSE_ALGORITHM_ES256.
 * \param[out] key_pair          The key pair. This must be freed.
 *
 * The key made here is fixed and just useful for testing.
 */
enum t_cose_err_t make_ossl_ecdsa_key_pair(
    int32_t            cose_algorithm_id,
    struct t_cose_key* key_pair)
{
    EC_GROUP* ossl_ec_group = NULL;
    enum t_cose_err_t  return_value;
    BIGNUM* ossl_private_key_bn = NULL;
    EC_KEY* ossl_ec_key = NULL;
    int                ossl_result;
    EC_POINT* ossl_pub_key_point = NULL;
    int                nid;
    const char* public_key;
    const char* private_key;

    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        nid = NID_X9_62_prime256v1;
        public_key = PUBLIC_KEY_prime256v1;
        private_key = PRIVATE_KEY_prime256v1;
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    /* Make a group for the particular EC algorithm */
    ossl_ec_group = EC_GROUP_new_by_curve_name(nid);
    if (ossl_ec_group == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Make an empty EC key object */
    ossl_ec_key = EC_KEY_new();
    if (ossl_ec_key == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Associate group with key object */
    ossl_result = EC_KEY_set_group(ossl_ec_key, ossl_ec_group);
    if (!ossl_result) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Make an instance of a big number to store the private key */
    ossl_private_key_bn = BN_new();
    if (ossl_private_key_bn == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }
    BN_zero(ossl_private_key_bn);

    /* Stuff the specific private key into the big num */
    ossl_result = BN_hex2bn(&ossl_private_key_bn, private_key);
    if (ossl_private_key_bn == 0) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Now associate the big num with the key object so we finally
     * have a key set up and ready for signing */
    ossl_result = EC_KEY_set_private_key(ossl_ec_key, ossl_private_key_bn);
    if (!ossl_result) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }


    /* Make an empty EC point into which the public key gets loaded */
    ossl_pub_key_point = EC_POINT_new(ossl_ec_group);
    if (ossl_pub_key_point == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Turn the serialized public key into an EC point */
    ossl_pub_key_point = EC_POINT_hex2point(ossl_ec_group,
        public_key,
        ossl_pub_key_point,
        NULL);
    if (ossl_pub_key_point == NULL) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Associate the EC point with key object */
    /* The key object has both the public and private keys in it */
    ossl_result = EC_KEY_set_public_key(ossl_ec_key, ossl_pub_key_point);
    if (ossl_result == 0) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    key_pair->k.key_ptr = ossl_ec_key;
    key_pair->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}

static teep_error_code_t get_signing_key_pair(struct t_cose_key* key_pair)
{
    enum t_cose_err_t return_value = make_ossl_ecdsa_key_pair(T_COSE_ALGORITHM_ES256, key_pair);
    if (return_value != T_COSE_SUCCESS) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    return TEEP_ERR_SUCCESS;
}
#endif

teep_error_code_t TeepSendCborMessage(void* sessionHandle, const char* mediaType, const UsefulBufC* buffer)
{
    // From draft-ietf-teep-protocol section 4.1.1:
    // 1.  Create a TEEP message according to the description below and
    //     populate it with the respective content.  (done by caller)
    // 2.  Create a COSE Header containing the desired set of Header
    //     Parameters.  The COSE Header MUST be valid per the [RFC8152]
    //     specification.
    // 3.  Create a COSE_Sign1 object using the TEEP message as the
    //     COSE_Sign1 Payload; all steps specified in [RFC8152] for creating
    //     a COSE_Sign1 object MUST be followed.

    teep_error_code_t err = TEEP_ERR_SUCCESS;
#ifdef TEEP_USE_COSE
    struct t_cose_key key_pair;
    err = get_signing_key_pair(&key_pair);
    if (err != TEEP_ERR_SUCCESS) {
        return err;
    }

    // Initialize for signing.
    struct t_cose_sign1_sign_ctx sign_ctx;
    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    // Sign.
    Q_USEFUL_BUF_MAKE_STACK_UB(signed_cose_buffer, 300);
    struct q_useful_buf_c signed_cose;
    enum t_cose_err_t return_value = t_cose_sign1_sign(
        &sign_ctx,
        *buffer,
        /* Non-const pointer and length of the
         * buffer where the completed output is
         * written to. The length here is that
         * of the whole buffer.
         */
        signed_cose_buffer,
        /* Const pointer and actual length of
         * the completed, signed and encoded
         * COSE_Sign1 message. This points
         * into the output buffer and has the
         * lifetime of the output buffer.
         */
        &signed_cose);
    if (return_value != T_COSE_SUCCESS) {
        return TEEP_ERR_PERMANENT_ERROR;
    }
    const char* output_buffer = (const char*)signed_cose.ptr;
    size_t output_buffer_length = signed_cose.len;
#else
    const char* output_buffer = (const char*)buffer->ptr;
    size_t output_buffer_length = buffer->len;
#endif

    // 4.  Prepend the COSE object with the TEEP CBOR tag to indicate that
    //     the CBOR-encoded message is indeed a TEEP message.
    // TODO: See https://github.com/ietf-teep/teep-protocol/issues/147

    oe_result_t result = ocall_QueueOutboundTeepMessage((int*)&err, sessionHandle, mediaType, output_buffer, output_buffer_length);
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
    err = TeepSendCborMessage(sessionHandle, mediaType, &encoded);
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



        QCBOREncode_OpenMap(&context);
        {
            /* Create a random token. */
            UsefulBuf_MAKE_STACK_UB(token, 8);
            oe_result_t result = oe_random(token.ptr, token.len);
            if (result != OE_OK) {
                return TEEP_ERR_TEMPORARY_ERROR;
            }
            QCBOREncode_AddBytesToMapN(&context, TEEP_LABEL_TOKEN, UsefulBuf_Const(token));

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

            err = TeepSendCborMessage(sessionHandle, TEEP_CBOR_MEDIA_TYPE, &update);
            free((void*)update.ptr);
            if (err != TEEP_ERR_SUCCESS) {
                return err;
            }
        }
    }

    return TEEP_ERR_SUCCESS;
}

teep_error_code_t TeepHandleCborSuccess(void* sessionHandle, QCBORDecodeContext* context)
{
    printf("Received Success message...\n");
    return TEEP_ERR_SUCCESS;
}

teep_error_code_t TeepHandleCborError(void* sessionHandle, QCBORDecodeContext* context)
{
    printf("Received Error message...\n");
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
    // TODO: See https://github.com/ietf-teep/teep-protocol/issues/147

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
    case TEEP_MESSAGE_SUCCESS:
        teeperr = TeepHandleCborSuccess(sessionHandle, &context);
        break;
    case TEEP_MESSAGE_ERROR:
        teeperr = TeepHandleCborError(sessionHandle, &context);
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
