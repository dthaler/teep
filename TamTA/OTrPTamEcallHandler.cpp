/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdlib.h>
#include <string.h>
#include "OTrPTam_t.h"

#include <stdbool.h>
#define FILE void
extern "C" {
#include "jansson.h"
#include "joseinit.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
#include "jose/jws.h"
#include "jose/b64.h"
#include "../OTrPTALib/common.h"
char* strdup(const char* str);
};
#include "../jansson/JsonAuto.h"

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
    if (request.AddStringToObject("rid", "<Unique request ID>") == NULL) {
        return NULL;
    }
    if (request.AddStringToObject("tid", "<transaction ID>") == NULL) {
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
    JsonAuto jwke(json_pack("{s:s}", "alg", "RS256"), true);
    if (jwke == NULL) {
        return NULL;
    }

    bool ok = jose_jwk_gen(NULL, jwke);
    if (!ok) {
        return NULL;
    }

    const char* tbsRequest = ComposeGetDeviceStateTBSRequest();
    if (tbsRequest == NULL) {
        return NULL;
    }
    size_t len = strlen(tbsRequest);
    json_t* b64Request = jose_b64_enc(tbsRequest, len);
    free((void*)tbsRequest);
    if (b64Request == NULL) {
        return NULL;
    }

    /* Create a signed message. */
    JsonAuto jws(json_pack("{s:o}", "payload", b64Request, true));
    if ((json_t*)jws == NULL) {
        return NULL;
    }
    ok = jose_jws_sig(
        NULL,    // Configuration context (optional)
        jws,     // The JWE object
        NULL,    // The JWE recipient object(s) or NULL
        jwke);   // The JWK(s) or JWKSet used for wrapping.
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

    const char* message = json_dumps(object, 0);
    return message;
}

int ecall_ProcessOTrPConnect(void)
{
    ocall_print("Received client connection\n");

    const char* message = ComposeGetDeviceStateRequest();
    size_t messageLength = strlen(message);

    ocall_print("Sending GetDeviceStateTBSRequest...\n");

    int err = 0;
    sgx_status_t sgxStatus = ocall_SendOTrPMessage(&err, message, messageLength);
    free((void*)message);
    if (sgxStatus != SGX_SUCCESS) {
        return sgxStatus;
    }

    return err;
}

int OTrPHandleGetDeviceStateResponse(const json_t* messageObject)
{
    if (!json_is_object(messageObject)) {
        return 1; /* Error */
    }

    return 0; /* no error */
}

int OTrPHandleTADependencyNotification(const json_t* messageObject)
{
    if (!json_is_object(messageObject)) {
        return 1; /* Error */
    }

    /* Get the JWS signed object. */
    json_t* jws = json_object_get(messageObject, "TADependencyNotification");
    if (jws == NULL) {
        return 1; /* Error */
    }
    const char* message = json_dumps(jws, 0);
    free((char*)message); // XXX

    /* Verify the signature. */
    JsonAuto jwkr(json_pack("{s:s}", "alg", "RS256"), true);
    if ((json_t*)jwkr == NULL) {
        return 1; /* Error */
    }
    if (!jose_jwk_gen(NULL, jwkr)) {
        return 1; /* Error */
    }

    char* payload = DecodeJWS(jws, jwkr);
    if (!payload) {
        return 1; /* Error */
    }

    JsonAuto object(json_loads(payload, 0, NULL));
    free(payload);
    if ((json_t*)object == NULL) {
        return 1; /* Error */
    }

    json_t* edsi = json_object_get(object, "edsi");
    if (edsi == NULL) {
        return 1; /* Error */
    }

    JsonAuto jwke(json_pack("{s:s}", "alg", "A128CBC-HS256"), true);
    if (jwke == NULL) {
        return NULL;
    }
    const char* jwkestr = json_dumps(jwke, 0);
    free((char*)jwkestr); // TODO: use this

    bool ok = jose_jwk_gen(NULL, jwke);
    if (!ok) {
        return NULL;
    }

    // Decrypt the edsi.
    size_t len = 0;
    char* dsistr = (char*)jose_jwe_dec(NULL, edsi, NULL, jwke, &len);
    if (dsistr == NULL) {
        return 1; /* Error */
    }
    json_error_t error;
    JsonAuto dsi(json_loads(dsistr, 0, &error), true);
    free(dsistr);
    if ((json_t*)dsi == NULL) {
        return 1; /* Error */
    }

    return 0; /* no error */
}

int OTrPHandleTADependencyNotifications(const json_t* messageObject)
{
    if (!json_is_array(messageObject)) {
        return 1; /* Error */
    }

    size_t index;
    json_t* value;
    json_array_foreach(messageObject, index, value) {
        int err = OTrPHandleTADependencyNotification(value);
        if (err != 0) {
            return err;
        }
    }

    return 0; /* no error */
}

int OTrPHandleMessage(const char* key, const json_t* messageObject)
{
    if (strcmp(key, "GetDeviceTEEStateTBSResponse") == 0) {
        return OTrPHandleGetDeviceStateResponse(messageObject);
    } 
    if (strcmp(key, "TADependencyNotifications") == 0) {
        return OTrPHandleTADependencyNotifications(messageObject);
    }

    /* Unrecognized message. */
    return 1;
}