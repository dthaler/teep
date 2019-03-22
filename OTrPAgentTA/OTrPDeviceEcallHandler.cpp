/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include "OTrPAgent_t.h"

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#define FILE void
extern "C" {
#include "jansson.h"
#include "joseinit.h"
#include "jose/b64.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
#include "jose/jws.h"
char* strdup(const char* str);
#include "../OTrPCommonTALib/common.h"
};
#include "../jansson/JsonAuto.h"

#ifdef OE_USE_SGX
# define TEE_NAME "Intel SGX"
#endif

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

#ifndef OE_USE_SGX
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
#endif

    /* Add tee. */
    JsonAuto tee = dsi.AddObjectToObject("tee");
    if (tee == NULL) {
        return NULL;
    }
    if (tee.AddStringToObject("name", TEE_NAME) == NULL) {
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

json_t* CreateNewJwk(const char* alg)
{
    JsonAuto jwk(json_pack("{s:s}", "alg", alg), true);
    if (jwk == NULL) {
        return NULL;
    }

    bool ok = jose_jwk_gen(NULL, jwk);
    if (!ok) {
        return NULL;
    }

    return json_incref(jwk);
}

json_t* CreateNewJwke()
{
    return CreateNewJwk("ECDH-ES+A128KW");
}

json_t* CreateNewJwkR1_5()
{
    return CreateNewJwk("RSA1_5");
}

json_t* CreateNewJwkRS256()
{
    return CreateNewJwk("RS256");
}

JsonAuto g_AgentKey;

json_t* GetAgentKey()
{
    if ((json_t*)g_AgentKey == NULL) {
        g_AgentKey = CreateNewJwkRS256();
    }
    return (json_t*)g_AgentKey;
}

/* Compose a TADependencyTBSNotification message. */
const char* ComposeTADependencyTBSNotification(void)
{
    json_t* jwk = GetAgentKey();
    const char* jwkestr = json_dumps(jwk, 0);
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
     * OCSP data again in the subsequent messages.
     * TODO: The value may be false if the device caches the TAM's signer certificate
     * and OCSP status.
     */
    if (request.AddStringToObject("signerreq", "true") == NULL) {
        return NULL;
    }

    if (AddEdsiToObject(request, jwk)) {
        return NULL;
    }
 
    /* Convert to message buffer. */
    const char* message = json_dumps(object, 0);
    return message;
}

/* Compose a TADependencyNotification message. */
const char* ComposeTADependencyNotification(void)
{
    json_t* jwk = GetAgentKey();

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
    bool ok = jose_jws_sig(
        NULL,    // Configuration context (optional)
        jws,     // The JWE object
        NULL,    // The JWE recipient object(s) or NULL
        jwk);   // The JWK(s) or JWKSet used for wrapping.
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

int ecall_ProcessOTrPConnect(void* sessionHandle)
{
    const char* message = NULL;
    size_t messageLength = 0;
    oe_result_t result = OE_OK;
    int err = 0;

    ocall_print("Connected to TAM\n");

    message = ComposeTADependencyNotification();
    if (message == NULL) {
        return 1; /* Error */
    }

    ocall_print("Sending TADependencyTBSNotification...\n");

    result = ocall_SendOTrPMessage(&err, sessionHandle, message);
    if (result != OE_OK) {
        return result;
    }

    return err;
}

/* Compose a GetDeviceTEEStateTBSResponse message. */
const char* ComposeGetDeviceTEEStateTBSResponse(
    const json_t* request,    // Request we're responding to.
    const char* statusValue,  // Status string to return.
    const json_t* jwk)       // Public key to encrypt with.
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

    if (AddEdsiToObject(response, jwk) == NULL) {
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
    const json_t* jwkTam,     // TAM Public key to encrypt with.
    const json_t* jwkAgent)   // Agent private key to sign with.
{
    /* Get a GetDeviceTEEStateTBSResponse. */
    const char* tbsResponse = ComposeGetDeviceTEEStateTBSResponse(request, statusValue, jwkTam);
    if (tbsResponse == NULL) {
        return NULL;
    }
#ifdef _DEBUG
    ocall_print("Sending TBS: ");
    ocall_print(tbsResponse);
    ocall_print("\n");
#endif
    size_t len = strlen(tbsResponse);
    json_t* b64Response = jose_b64_enc(tbsResponse, len);
    free((void*)tbsResponse);
    if (b64Response == NULL) {
        return NULL;
    }

    // Create a signed message.
    JsonAuto jws(json_pack("{s:o}", "payload", b64Response, true));
    if ((json_t*)jws == NULL) {
        return NULL;
    }
    bool ok = jose_jws_sig(
        NULL,    // Configuration context (optional)
        jws,     // The JWE object
        NULL,
        jwkAgent);   // The JWK(s) or JWKSet used for wrapping.
    if (!ok) {
        return NULL;
    }

    return jws.Detach();
}

/* Compose a GetDeviceStateResponse message. */
const char* ComposeGetDeviceStateResponse(
    const json_t* request,    // Request we're responding to.
    const char* statusValue,  // Status string to return.
    const json_t* jwkTam,     // TAM public key to encrypt with.
    const json_t* jwkAgent)   // Agent private key to sign with.
{
    JsonAuto jws(ComposeGetDeviceTEEStateResponse(request, statusValue, jwkTam, jwkAgent), true);
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

int OTrPHandleGetDeviceStateRequest(void* sessionHandle, const json_t* request)
{
    if (!json_is_object(request)) {
        return 1; /* Error */
    }

    int err = 1;
    oe_result_t result;
    const char* statusValue = "fail";

    /* 1.  Validate JSON message signing.  If it doesn't pass, an error message is returned. */
    char* payload = DecodeJWS(request, NULL);
    if (!payload) {
        return 1; /* Error */
    }
#ifdef _DEBUG
    ocall_print("Received TBS: ");
    ocall_print(payload);
    ocall_print("\n");
#endif
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
    JsonAuto jwkTam(CreateNewJwkR1_5(), true); // TODO: fix this

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

    json_t* jwkAgent = GetAgentKey();
    const char* message = ComposeGetDeviceStateResponse(tbsRequest, statusValue, jwkTam, jwkAgent);
    if (message == NULL) {
        return 1; /* Error */
    }

    ocall_print("Sending GetDeviceStateResponse...\n");

    result = ocall_SendOTrPMessage(&err, sessionHandle, message);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

int OTrPHandleMessage(void* sessionHandle, const char* key, const json_t* messageObject)
{
    if (strcmp(key, "GetDeviceStateRequest") == 0) {
        return OTrPHandleGetDeviceStateRequest(sessionHandle, messageObject);
    }

    /* Unrecognized message. */
    return 1;
}

int ecall_RequestTA(
    const char* taid,
    const char* tamUri)
{
    int err = 0;
    oe_result_t result = OE_OK;
    size_t responseLength = 0;

    // TODO: See whether taid is already installed.
    // For now we skip this step and pretend it's not.
    bool isInstalled = false;

    if (isInstalled) {
        // Already installed, nothing to do.
        // This counts as "pass no data back" in the broker spec.
        return 0;
    }

    // TODO: we may want to modify the TAM URI here.

    // TODO: see whether we already have a TAM cert we trust.
    // For now we skip this step and say we don't.
    bool haveTrustedTamCert = false;

    if (!haveTrustedTamCert) {
        // Pass back a TAM URI with no buffer.
        result = ocall_Connect(&err, tamUri);
        if (result != OE_OK) {
            return result;
        }
        if (err != 0) {
            return err;
        }
    } else {
        // TODO: implement going on to the next message.
        assert(false);
    }

    return err;
}