/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include "OTrPTam_t.h"

#include <stdbool.h>
#include <string.h>
#define FILE void
extern "C" {
#include "jansson.h"
#include "joseinit.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
#include "jose/jws.h"
#include "jose/b64.h"
#include "../OTrPCommonTALib/common.h"
    char* strdup(const char* str);
};
#include "../jansson/JsonAuto.h"

#define UNIQUE_ID_LEN 16

/* Try to constrict a globally unique value. */
json_t* GetNewGloballyUniqueID(void)
{
    /* Create a random 16-byte value. */
    unsigned char value[UNIQUE_ID_LEN];
    oe_result_t result = oe_random(value, UNIQUE_ID_LEN);
    if (result != OE_OK) {
        return NULL;
    }

    /* Base64-encode it into a string. */
    return jose_b64_enc(value, sizeof(value));
}

/* Construct a unique request ID.  The OTrP spec does not say what
 * the scope of uniqueness needs to be, but we currently try to use
 * globally unique value.
 */
json_t* GetNewRequestID(void)
{
    return GetNewGloballyUniqueID();
}

/* Construct a unique transaction ID.  The OTrP spec does not say what
 * the scope of uniqueness needs to be, but we currently try to use
 * a globally unique value.
 */
json_t* GetNewTransactionID(void)
{
    return GetNewGloballyUniqueID();
}

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

/* Compose a GetDeviceStateTBSRequest message. */
const char* ComposeGetDeviceStateTBSRequest(void)
{
    JsonAuto object(json_object(), true);
    if (object == NULL) {
        return NULL;
    }
    JsonAuto request = object.AddObjectToObject("GetDeviceStateTBSRequest");
    if (request == NULL) {
        return NULL;
    }
    if (request.AddStringToObject("ver", "1.0") == NULL) {
        return NULL;
    }
    if (request.AddObjectToObject("rid", GetNewRequestID()) == NULL) {
        return NULL;
    }
    if (request.AddObjectToObject("tid", GetNewTransactionID()) == NULL) {
        return NULL;
    }
    JsonAuto ocspdat = request.AddArrayToObject("ocspdat");
    if (ocspdat == NULL) {
        return NULL;
    }
    /* TODO: Fill in list of OCSP stapling data. */

    /* supportedsigalgs is optional, so omit for now. */

    /* Convert to message buffer. */
    const char* message = json_dumps(object, 0);
    if (message == NULL) {
        return NULL;
    }
    return strdup(message);
}

const char* ComposeGetDeviceStateRequest(void)
{
    json_t* jwk = GetTamSigningKey();

    /* Compose a raw GetDeviceState request to be signed. */
    const char* tbsRequest = ComposeGetDeviceStateTBSRequest();
    if (tbsRequest == NULL) {
        return NULL;
    }
#ifdef _DEBUG
    ocall_print("Sending TBS: ");
    ocall_print(tbsRequest);
#endif

    /* Base64 encode it. */
    size_t len = strlen(tbsRequest);
    json_t* b64Request = jose_b64_enc(tbsRequest, len);
    free((void*)tbsRequest);
    if (b64Request == NULL) {
        return NULL;
    }

    /* Create the signed message. */
    JsonAuto jws(json_pack("{s:o}", "payload", b64Request), true);
    if ((json_t*)jws == NULL) {
        return NULL;
    }

    JsonAuto sig(json_object(), true);
    JsonAuto header = sig.AddObjectToObject("header");
    if ((json_t*)header == NULL) {
        return NULL;
    }
    void* certChain = "abc"; // TODO
    size_t certChainLen = 3; // TODO
    if (json_object_set_new(header, "x5c", jose_b64_enc(certChain, certChainLen)) < 0) {
        return NULL;
    }

    bool ok = jose_jws_sig(
        NULL,    // Configuration context (optional)
        jws,     // The JWE object
        sig,     // The JWE recipient object(s) or NULL
        jwk);   // The JWK(s) or JWKSet used for wrapping.
    if (!ok) {
        return NULL;
    }

    /* Create the final GetDeviceStateRequest message. */
    JsonAuto object(json_object(), true);
    if ((json_t*)object == NULL) {
        return NULL;
    }
    if (object.AddObjectToObject("GetDeviceStateRequest", jws) == NULL) {
        return NULL;
    }

    /* Serialize it to a single string. */
    const char* message = json_dumps(object, 0);
    return message;
}

/* Handle a new incoming connection from a device. */
int ecall_ProcessOTrPConnect(void* sessionHandle)
{
    ocall_print("Received client connection\n");

    const char* message = ComposeGetDeviceStateRequest();
    if (message == NULL) {
        return 1; /* Error */
    }

    ocall_print("Sending GetDeviceStateRequest...\n");

    int err = 0;
    oe_result_t result = ocall_SendOTrPMessage(&err, sessionHandle, message);
    free((void*)message);
    if (result != OE_OK) {
        return result;
    }

    return err;
}

/* Handle a GetDeviceTEEStateResponse from an OTrP Agent. */
int OTrPHandleGetDeviceTEEStateResponse(void* sessionHandle, const json_t* messageObject)
{
    if (!json_is_object(messageObject)) {
        return 1; /* Error */
    }

    /* Get the JWS signed object. */
    json_t* jws = json_object_get(messageObject, "GetDeviceTEEStateResponse");
    if (jws == NULL) {
        return 1; /* Error */
    }
#ifdef _DEBUG
    const char* message = json_dumps(jws, 0);
    free((char*)message);
#endif

    /* Parse the JSON "payload" property and decrypt the JSON element
     * "edsi".  The decrypted message contains the TEE signer
     * certificate.
     */

    char* payload = DecodeJWS(jws, nullptr);
    if (payload == NULL) {
        return 1; /* Error */
    }

    JsonAuto object(json_loads(payload, 0, NULL));
    free(payload);
    if ((json_t*)object == NULL) {
        return 1; /* Error */
    }

    json_t* tbs = json_object_get(object, "GetDeviceTEEStateTBSResponse");
    if (tbs == NULL || !json_is_object(tbs)) {
        return 1; /* Error */
    }

    json_t* edsi = json_object_get(tbs, "edsi");
    if (edsi == NULL || !json_is_object(edsi)) {
        return 1; /* Error */
    }

    /* Decrypt the edsi. */
    json_t* jwkEncryption = GetTamEncryptionKey();
    size_t len = 0;
    char* dsistr = (char*)jose_jwe_dec(NULL, edsi, NULL, jwkEncryption, &len);
    if (dsistr == NULL) {
        return 1; /* Error */
    }
    json_error_t error;
    JsonAuto dsi(json_loads(dsistr, 0, &error), true);
    free(dsistr);
    if ((json_t*)dsi == NULL) {
        return 1; /* Error */
    }

    /* Verify the signature. */
    json_t* jwkSigning = GetTamSigningKey();
    // TODO

    return 0; /* no error */
}

/* Handle a GetDeviceStateResponse from an OTrP Agent. */
int OTrPHandleGetDeviceStateResponse(void* sessionHandle, const json_t* messageObject)
{
    if (!json_is_array(messageObject)) {
        return 1; /* Error */
    }

    // Parse to get list of GetDeviceTEEStateResponse JSON objects.
    size_t index;
    json_t* value;
    json_array_foreach(messageObject, index, value) {
        int err = OTrPHandleGetDeviceTEEStateResponse(sessionHandle, value);
        if (err != 0) {
            return err;
        }
    }

    return 0; /* no error */
}

/* Handle an incoming message from an OTrP Agent. */
int OTrPHandleMessage(void* sessionHandle, const char* key, const json_t* messageObject)
{
    if (strcmp(key, "GetDeviceStateResponse") == 0) {
        return OTrPHandleGetDeviceStateResponse(sessionHandle, messageObject);
    }

    /* Unrecognized message. */
    return 1;
}
