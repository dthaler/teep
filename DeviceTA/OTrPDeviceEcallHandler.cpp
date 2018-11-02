/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdlib.h>
#include <string.h>
#include "OTrPDevice_t.h"
#include "sgx_trts.h"

#include <stdbool.h>
#define FILE void
extern "C" {
#include "jansson.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
extern char* strdup(const char* str);
};
#include "../jansson/JsonAuto.h"

/* Compose a DeviceStateInformation message. */
const char* ComposeDeviceStateInformation(void)
{
    JsonAuto object(json_object(), true);
    if (object == NULL) {
        return NULL;
    }

    JsonAuto dsi = object.AddObjectToObject("dsi");
    if (dsi == NULL) {
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

/* Compose a TADependencyNotification message. */
const char* ComposeTADependencyTBSNotification(void)
{
    const char* dsi = ComposeDeviceStateInformation();
    if (dsi == NULL) {
        return NULL;
    }
    size_t dsilen = strlen(dsi); // TODO: Include NULL byte?
    free((void*)dsi); // TODO: use this
    dsi = NULL;

    JsonAuto jwke(json_pack("{s:s}", "alg", "ECDH-ES+A128KW"), true);
    if (jwke == NULL) {
        return NULL;
    }
    const char* jwkestr = json_dumps(jwke, 0);
    free((char*)jwkestr); // TODO: use this

    bool ok = jose_jwk_gen(NULL, jwke);
    if (ok) {
        json_auto_t *jwe = json_object();

        ok = jose_jwe_enc(
            NULL,    // Configuration context (optional)
            jwe,     // The JWE object
            NULL,    // The JWE recipient object(s) or NULL
            jwke,    // The JWK(s) or JWKSet used for wrapping.
            dsi,     // The plaintext.
            dsilen); // The length of the plaintext.
    }

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
    JsonAuto edsi = request.AddObjectToObject("edsi");
    if (edsi == NULL) {
        return NULL;
    }
    if (edsi.AddStringToObject("protected", "<BASE64URL encoding of encryption algorithm header JSON data>") == NULL) {
        return NULL;
    }
    JsonAuto recipients = edsi.AddArrayToObject("recipients");
    if (recipients == NULL) {
        return NULL;
    }
    JsonAuto recipient = recipients.AddObjectToArray();
    if (recipient == NULL) {
        return NULL;
    }
    JsonAuto edsi_header = recipient.AddObjectToObject("header");
    if (edsi_header == NULL) {
        return NULL;
    }
    if (edsi_header.AddStringToObject("alg", "RSA1_5") == NULL) {
        return NULL;
    }
    if (recipient.AddStringToObject("encrypted_key", "<encrypted value of CEK>") == NULL) {
        return NULL;
    }
    if (edsi.AddStringToObject("iv", "<BASE64URL encoded IV data>") == NULL) {
        return NULL;
    }
    if (edsi.AddStringToObject("ciphertext", "<Encrypted data over the JSON object of dsi (BASE64URL)>") == NULL) {
        return NULL;
    }
    if (edsi.AddStringToObject("tag", "<JWE authentication tag (BASE64URL)>") == NULL) {
        return NULL;
    }

    /* Convert to message buffer. */
    const char* message = json_dumps(object, 0);
    return message;
}

int ecall_ProcessOTrPConnect(void)
{
    const char* message = NULL;
    size_t messageLength = 0;
    sgx_status_t sgxStatus = SGX_SUCCESS;
    int err = 0;

    ocall_print("Received client connection\n");

    message = ComposeTADependencyTBSNotification();
    if (message == NULL) {
        return 1; /* Error */
    }
    messageLength = strlen(message);

    ocall_print("Sending TADependencyTBSNotification...\n");

    sgxStatus = ocall_SendOTrPMessage(&err, message, messageLength);
    if (sgxStatus != SGX_SUCCESS) {
        return sgxStatus;
    }

    return err;
}

/* Compose a GetDeviceStateResponse message. */
const char* ComposeGetDeviceStateResponse(const json_t* request, const char* statusValue)
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

    /* TODO: fill in edsi info */

    /* Convert to message buffer. */
    const char* message = json_dumps(object, 0);
    if (message == NULL) {
        return NULL;
    }

    return strdup(message);
}


int OTrPHandleGetDeviceStateRequest(const json_t* request)
{
    int err = 1;
    sgx_status_t sgxStatus;
    const char* statusValue = "fail";

    /* 1.  Validate JSON message signing.  If it doesn't pass, an error message is returned. */
    /* TODO */

    /* 2.  Validate that the request TAM certificate is chained to a trusted
     *     CA that the TEE embeds as its trust anchor.
     *
     *     *  Cache the CA OCSP stapling data and certificate revocation
     *        check status for other subsequent requests.
     *
     *     *  A TEE can use its own clock time for the OCSP stapling data
     *        validation.
     */
    /* TODO */

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

    const char* message = ComposeGetDeviceStateResponse(request, statusValue);

    ocall_print("Sending GetDeviceTEEStateTBSResponse...\n");

    sgxStatus = ocall_SendOTrPMessage(&err, message, strlen(message));
    if (sgxStatus != SGX_SUCCESS) {
        return sgxStatus;
    }
    return err;
}

int ecall_ProcessOTrPMessage(
    const char* message,
    int messageLength)
{
    int err = 1;
    char *newstr = NULL;

    if (messageLength < 1) {
        return 1; /* error */
    }

    /* Verify string is null-terminated. */
    const char* str = message;
    if (message[messageLength - 1] == 0) {
        str = message;
    } else {
        newstr = (char*)malloc(messageLength + 1);
        if (newstr == NULL) {
            return 1; /* error */
        }
        memcpy(newstr, message, messageLength);
        newstr[messageLength] = 0;
        str = newstr;
    }

    json_error_t error;
    JsonAuto object(json_loads(str, 0, &error), true);

    free(newstr);
    newstr = NULL;

    if ((object == NULL) || !json_is_object((json_t*)object)) {
        return 1; /* Error */
    }
    const char* key = json_object_iter_key(json_object_iter(object));

    ocall_print("Received ");
    ocall_print(key);
    ocall_print("\n");

    JsonAuto messageObject = json_object_get(object, key);
    if (!json_is_object((json_t*)messageObject)) {
        return 1; /* Error */
    }

    if (strcmp(key, "GetDeviceStateTBSRequest") == 0) {
        err = OTrPHandleGetDeviceStateRequest(messageObject);
    } else {
        /* Unrecognized message. */
        err = 1;
    }

    return err;
}
