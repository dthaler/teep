/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdlib.h>
#include <string.h>
#include "OTrPDevice_t.h"
#include "sgx_trts.h"

#include <stdbool.h>
#define FILE void
extern "C" {
#include "jansson.h"
#include "joseinit.h"
#include "jose/b64.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
#include "jose/jws.h"
char* strdup(const char* str);
#include "../OTrPTALib/common.h"
};
#include "../jansson/JsonAuto.h"

/* Compose a DeviceStateInformation message. */
const char* ComposeDeviceStateInformation(void)
{
    JsonAuto object(json_object(), true);
    if ((json_t*)object == NULL) {
        return NULL;
    }

    JsonAuto dsi = object.AddObjectToObject("dsi");
    if ((json_t*)dsi == NULL) {
        return NULL;
    }

    /* Add tfwdata. */
    JsonAuto tfwdata = dsi.AddObjectToObject("tfwdata");
    if (tfwdata == NULL) {
        return NULL;
    }
    if (tfwdata.AddStringToObject("tbs", "<TFW to be signed data is the tid>") == NULL) {
        return NULL;
    }
    if (tfwdata.AddStringToObject("cert", "<BASE64 encoded TFW certificate>") == NULL) {
        return NULL;
    }
    if (tfwdata.AddStringToObject("sigalg", "Signing method") == NULL) {
        return NULL;
    }
    if (tfwdata.AddStringToObject("sig", "<TFW signed data, BASE64 encoded>") == NULL) {
        return NULL;
    }

    /* Add tee. */
    JsonAuto tee = dsi.AddObjectToObject("tee");
    if (tee == NULL) {
        return NULL;
    }
    if (tee.AddStringToObject("name", "<TEE name>") == NULL) {
        return NULL;
    }
    if (tee.AddStringToObject("ver", "<TEE version>") == NULL) {
        return NULL;
    }
    if (tee.AddStringToObject("cert", "<BASE64 encoded TEE cert>") == NULL) {
        return NULL;
    }
    if (tee.AddStringToObject("cacert", "<JSON array value of CA certificates up to the root CA>") == NULL) {
        return NULL;
    }

    // sdlist is optional, so we omit it.

    JsonAuto teeaiklist = tee.AddArrayToObject("teeaiklist");
    if (teeaiklist == NULL) {
        return NULL;
    }
    JsonAuto teeaik = teeaiklist.AddObjectToArray();
    if (teeaik == NULL) {
        return NULL;
    }
    if (teeaik.AddStringToObject("spaik", "<SP AIK public key, BASE64 encoded>") == NULL) {
        return NULL;
    }
    if (teeaik.AddStringToObject("spaiktype", "RSA") == NULL) { // RSA or ECC
        return NULL;
    }
    if (teeaik.AddStringToObject("spid", "<sp id>") == NULL) {
        return NULL;
    }

    JsonAuto talist = tee.AddArrayToObject("talist");
    if (talist == NULL) {
        return NULL;
    }
    JsonAuto ta = talist.AddObjectToArray();
    if (ta == NULL) {
        return NULL;
    }
    if (ta.AddStringToObject("taid", "<TA application identifier>") == NULL) {
        return NULL;
    }
    // taname is optional

    /* Convert to message buffer. */
    const char* message = json_dumps(object, 0);
    if (message == NULL) {
        return NULL;
    }
    return strdup(message);
}

json_t* AddEdsiToObject(JsonAuto& request, const json_t* jwke)
{
    const char* dsi = ComposeDeviceStateInformation();
    if (dsi == NULL) {
        return NULL;
    }
    size_t dsilen = strlen(dsi);

    JsonAuto jwe(json_object(), true);
    bool ok = jose_jwe_enc(
        NULL,    // Configuration context (optional)
        jwe,     // The JWE object
        NULL,    // The JWE recipient object(s) or NULL
        jwke,    // The JWK(s) or JWKSet used for wrapping.
        dsi,     // The plaintext.
        dsilen); // The length of the plaintext.

    free((void*)dsi);
    dsi = NULL;

    if (!ok) {
        return NULL;
    }
    return request.AddObjectToObject("edsi", jwe);
}

json_t* CreateNewJwke()
{
    JsonAuto jwke(json_pack("{s:s}", "alg", "ECDH-ES+A128KW"), true);
    if (jwke == NULL) {
        return NULL;
    }

    bool ok = jose_jwk_gen(NULL, jwke);
    if (!ok) {
        return NULL;
    }

    return json_incref(jwke);
}

/* Compose a TADependencyTBSNotification message. */
const char* ComposeTADependencyTBSNotification(void)
{
    JsonAuto jwke(CreateNewJwke(), true);
    if (jwke == NULL) {
        return NULL;
    }
    const char* jwkestr = json_dumps(jwke, 0);
    free((char*)jwkestr); // TODO: use this

    JsonAuto object(json_object(), true);
    if (object == NULL) {
        return NULL;
    }
    JsonAuto request = object.AddObjectToObject("TADependencyTBSNotification");
    if (request == NULL) {
        return NULL;
    }
    if (request.AddStringToObject("ver", "1.0") == NULL) {
        return NULL;
    }

    /* Signerreq should be true if the TAM should send its signer certificate and
    * OCSP data again in the subsequent messages.  The value may be
    * false if the device caches the TAM's signer certificate and OCSP
    * status.
    */
    if (request.AddStringToObject("signerreq", "true") == NULL) {
        return NULL;
    }

    if (AddEdsiToObject(request, jwke)) {
        return NULL;
    }
 
    /* Convert to message buffer. */
    const char* message = json_dumps(object, 0);
    return message;
}

/* Compose a TADependencyNotification message. */
const char* ComposeTADependencyNotification(void)
{
    JsonAuto jwke(json_pack("{s:s}", "alg", "RS256"), true);
    if (jwke == NULL) {
        return NULL;
    }

    bool ok = jose_jwk_gen(NULL, jwke);
    if (!ok) {
        return NULL;
    }

    /* Get a TADependencyTBSNotification. */
    const char* tbsNotification = ComposeTADependencyTBSNotification();
    if (tbsNotification == NULL) {
        return NULL;
    }
    size_t len = strlen(tbsNotification);
    json_t* b64Notification = jose_b64_enc(tbsNotification, len);
    free((void*)tbsNotification);
    if (b64Notification == NULL) {
        return NULL;
    }

    /* Create a signed message. */
    JsonAuto jws(json_pack("{s:o}", "payload", b64Notification, true));
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

    /* Create the final TADependencyNotification message. */
    JsonAuto object(json_object(), true);
    if ((json_t*)object == NULL) {
        return NULL;
    }
    JsonAuto dnlist = object.AddArrayToObject("TADependencyNotifications");
    if (dnlist == NULL) {
        return NULL;
    }
    JsonAuto dn = dnlist.AddObjectToArray();
    if (dn == NULL) {
        return NULL;
    }
    if (dn.AddObjectToObject("TADependencyNotification", jws) == NULL) {
        return NULL;
    }

    const char* message = json_dumps(object, 0);
    return message;
}

int ecall_ProcessOTrPConnect(void)
{
    const char* message = NULL;
    size_t messageLength = 0;
    sgx_status_t sgxStatus = SGX_SUCCESS;
    int err = 0;

    ocall_print("Connected to TAM\n");

    message = ComposeTADependencyNotification();
    if (message == NULL) {
        return 1; /* Error */
    }

    ocall_print("Sending TADependencyTBSNotification...\n");

    sgxStatus = ocall_SendOTrPMessage(&err, message);
    if (sgxStatus != SGX_SUCCESS) {
        return sgxStatus;
    }

    return err;
}

/* Compose a GetDeviceTEEStateTBSResponse message. */
const char* ComposeGetDeviceTEEStateTBSResponse(
    const json_t* request,    // Request we're responding to.
    const char* statusValue,  // Status string to return.
    const json_t* jwke)       // Key to encrypt with.
{
    /* Compose a GetDeviceStateResponse message. */
    JsonAuto object(json_object(), true);
    if (object == NULL) {
        return NULL;
    }
    JsonAuto response = object.AddObjectToObject("GetDeviceTEEStateTBSResponse");
    if (response == NULL) {
        return NULL;
    }
    if (response.AddStringToObject("ver", "1.0") == NULL) {
        return NULL;
    }
    if (response.AddStringToObject("status", statusValue) == NULL) {
        return NULL;
    }

    /* Copy rid from request. */
    json_t* rid = json_object_get(request, "rid");
    if (!json_is_string(rid) || (json_string_value(rid) == NULL)) {
        return NULL;
    }
    if (response.AddStringToObject("rid", json_string_value(rid)) == NULL) {
        return NULL;
    }

    /* Copy tid from request. */
    json_t* tid = json_object_get(request, "tid");
    if (!json_is_string(tid) || (json_string_value(tid) == NULL)) {
        return NULL;
    }
    if (response.AddStringToObject("tid", json_string_value(tid)) == NULL) {
        return NULL;
    }

    /* Support for signerreq false is optional, so pass true for now. */
    if (response.AddStringToObject("signerreq", "true") == NULL) {
        return NULL;
    }

    JsonAuto edsi = response.AddObjectToObject("edsi");
    if (edsi == NULL) {
        return NULL;
    }

    if (AddEdsiToObject(response, jwke) == NULL) {
        return NULL;
    }

    /* Convert to message buffer. */
    const char* message = json_dumps(object, 0);
    if (message == NULL) {
        return NULL;
    }

    return strdup(message);
}

/* Compose a GetDeviceTEEStateResponse message. */
json_t* ComposeGetDeviceTEEStateResponse(
    const json_t* request,    // Request we're responding to.
    const char* statusValue,  // Status string to return.
    const json_t* jwke)       // Key to encrypt with.
{
    /* Get a GetDeviceTEEStateTBSResponse. */
    const char* tbsResponse = ComposeGetDeviceTEEStateTBSResponse(request, statusValue, jwke);
    if (tbsResponse == NULL) {
        return NULL;
    }
    size_t len = strlen(tbsResponse);
    json_t* b64Response = jose_b64_enc(tbsResponse, len);
    free((void*)tbsResponse);
    if (b64Response == NULL) {
        return NULL;
    }

    /* Create a signed message. */
    JsonAuto jws(json_pack("{s:o}", "payload", b64Response, true));
    if ((json_t*)jws == NULL) {
        return NULL;
    }
    bool ok = jose_jws_sig(
        NULL,    // Configuration context (optional)
        jws,     // The JWE object
        NULL,    // The JWE recipient object(s) or NULL
        jwke);   // The JWK(s) or JWKSet used for wrapping.
    if (!ok) {
        return NULL;
    }

    return jws.Detach();
}

/* Compose a GetDeviceStateResponse message. */
const char* ComposeGetDeviceStateResponse(
    const json_t* request,    // Request we're responding to.
    const char* statusValue,  // Status string to return.
    const json_t* jwke)       // Key to encrypt with.
{
    JsonAuto jws(ComposeGetDeviceTEEStateResponse(request, statusValue, jwke), true);
    if ((json_t*)jws == NULL) {
        return NULL;
    }

    /* Create the final GetDeviceStateResponse message. */
    JsonAuto object(json_object(), true);
    if ((json_t*)object == NULL) {
        return NULL;
    }
    JsonAuto dnlist = object.AddArrayToObject("GetDeviceStateResponse");
    if (dnlist == NULL) {
        return NULL;
    }
    JsonAuto dn = dnlist.AddObjectToArray();
    if (dn == NULL) {
        return NULL;
    }
    if (dn.AddObjectToObject("GetDeviceTEEStateResponse", jws) == NULL) {
        return NULL;
    }

    const char* message = json_dumps(object, 0);
    return message;
}

int OTrPHandleGetDeviceStateRequest(const json_t* request)
{
    if (!json_is_object(request)) {
        return 1; /* Error */
    }

    int err = 1;
    sgx_status_t sgxStatus;
    const char* statusValue = "fail";

    /* 1.  Validate JSON message signing.  If it doesn't pass, an error message is returned. */
    char* payload = DecodeJWS(request, NULL);
    if (!payload) {
        return 1; /* Error */
    }
    json_error_t error;
    JsonAuto object(json_loads(payload, 0, &error), true);
    if ((json_t*)object == NULL) {
        return 1;
    }

    /* 2.  Validate that the request TAM certificate is chained to a trusted
     *     CA that the TEE embeds as its trust anchor.
     *
     *     *  Cache the CA OCSP stapling data and certificate revocation
     *        check status for other subsequent requests.
     *
     *     *  A TEE can use its own clock time for the OCSP stapling data
     *        validation.
     */
    const char* debug = json_dumps(object, 0);
    free((char*)debug); // TODO: use this
    json_t* tbsRequest = json_object_get(object, "GetDeviceStateTBSRequest");
    if (tbsRequest == NULL) {
        return 1;
    }

    // Get the TAM's cert from the request.
    json_t* header = json_object_get(request, "header");
    if (header == NULL) {
        return 1;
    }
    json_t* x5c = json_object_get(header, "x5c");
    if (x5c == NULL) {
        return 1;
    }
    size_t certChainSize = jose_b64_dec(x5c, NULL, 0);
    void* certChain = malloc(certChainSize);
    if (certChain == NULL) {
        return 1;
    }
    if (jose_b64_dec(x5c, certChain, certChainSize) != certChainSize) {
        free(certChain);
        return 1;
    }
    // certChain is now a certificate chain that chains up to the root CA certificate.

    // TODO: Validate that the request TAM certificate is chained to a trusted
    //       CA that the TEE embeds as its trust anchor.

    // Get the TAM's public key from the TAM's cert.
    // TODO: Get the TAM's public key from the TAM's cert.
    free(certChain);

    // Create a JWK from the server's public key.
    JsonAuto jwke(CreateNewJwke(), true); // TODO: fix this

    /* TODO: Cache the CA OCSP stapling data and certificate revocation
    *        check status for other subsequent requests.
    */

    /* 3.  Optionally collect Firmware signed data
     *
     *     *  This is a capability in ARM architecture that allows a TEE to
     *        query Firmware to get FW signed data.It isn't required for
     *        all TEE implementations.When TFW signed data is absent, it
     *        is up to a TAM's policy how it will trust a TEE.
     */
     /* Do nothing since this is optional. */

     /*
      * 4.  Collect SD information for the SD owned by this TAM
      */
      /* TODO */

    statusValue = "pass";

    const char* message = ComposeGetDeviceStateResponse(tbsRequest, statusValue, jwke);
    if (message == NULL) {
        return 1; /* Error */
    }

    ocall_print("Sending GetDeviceStateResponse...\n");

    sgxStatus = ocall_SendOTrPMessage(&err, message);
    if (sgxStatus != SGX_SUCCESS) {
        return sgxStatus;
    }
    return err;
}

int OTrPHandleMessage(const char* key, const json_t* messageObject)
{
    if (strcmp(key, "GetDeviceStateRequest") == 0) {
        return OTrPHandleGetDeviceStateRequest(messageObject);
    }

    /* Unrecognized message. */
    return 1;
}
