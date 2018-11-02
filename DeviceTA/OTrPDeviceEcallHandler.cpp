/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdlib.h>
#include <string.h>
#include "OTrPDevice_t.h"
#include "sgx_trts.h"
#include "../external/cJSON/cJSON.h"

#include <stdbool.h>
#define FILE void
extern "C" {
#include "../external/jansson/include/jansson.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
extern char* strdup(const char* str);
};

class JsonAuto {
public:
    JsonAuto() {
        ptr = NULL;
    }
    JsonAuto(JsonAuto& value) {
        ptr = json_incref(value);
    }
    JsonAuto(json_t* value, bool donateReference = false) {
        if (donateReference || !value) {
            ptr = value;
        } else {
            ptr = json_incref(value);
        }
    }
    ~JsonAuto() {
        if (ptr != NULL) {
            json_decref(ptr);
        }
    }
    operator json_t*() {
        return ptr;
    }
    JsonAuto& operator =(json_t* value) {
        if (ptr != NULL) {
            json_decref(ptr);
        }
        ptr = json_incref(value);
    }
    json_t* AddStringToObject(const char* name, const char* value) {
        JsonAuto str = json_string(value);
        if (str == NULL) {
            return NULL;
        }
        if (json_object_set(ptr, name, str)) {
            return NULL;
        }
        return str;
    }
    json_t* AddObjectToObject(const char* name) {
        JsonAuto object = json_object();
        if (object == NULL) {
            return NULL;
        }
        if (json_object_set(ptr, name, object)) {
            return NULL;
        }
        return object;
    }
    json_t* AddArrayToObject(const char* name) {
        JsonAuto object = json_array();
        if (object == NULL) {
            return NULL;
        }
        if (json_object_set(ptr, name, object)) {
            return NULL;
        }
        return object;
    }
    json_t* AddObjectToArray() {
        JsonAuto object = json_object();
        if (object == NULL) {
            return NULL;
        }
        if (json_array_append(ptr, object)) {
            return NULL;
        }
        return object;
    }
private:
    json_t* ptr;
};

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

int OTrPHandleGetDeviceStateRequest(const cJSON* request)
{
    int err = 1;
    sgx_status_t sgxStatus;
    cJSON* object = NULL;
    cJSON* response;
    cJSON* edsi;
    cJSON* rid;
    cJSON* tid;
    const char* message;
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

    /* Compose a GetDeviceStateResponse message. */
    object = cJSON_CreateObject();
    if (object == NULL) {
        goto Error;
    }
    response = cJSON_AddObjectToObject(object, "GetDeviceTEEStateTBSResponse");
    if (request == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(response, "ver", "1.0") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(response, "status", statusValue) == NULL) {
        goto Error;
    }
    
    /* Copy rid from request. */
    rid = cJSON_GetObjectItemCaseSensitive(request, "rid");
    if (!cJSON_IsString(rid) || (rid->valuestring == NULL)) {
        goto Error;
    }
    if (cJSON_AddStringToObject(response, "rid", rid->valuestring) == NULL) {
        goto Error;
    }

    /* Copy tid from request. */
    tid = cJSON_GetObjectItemCaseSensitive(request, "tid");
    if (!cJSON_IsString(tid) || (tid->valuestring == NULL)) {
        goto Error;
    }
    if (cJSON_AddStringToObject(response, "tid", tid->valuestring) == NULL) {
        goto Error;
    }

    /* Support for signerreq false is optional, so pass true for now. */
    if (cJSON_AddStringToObject(response, "signerreq", "true") == NULL) {
        goto Error;
    }

    edsi = cJSON_AddObjectToObject(response, "edsi");
    if (edsi == NULL) {
        goto Error;
    }

    /* TODO: fill in edsi info */

    /* Convert to message buffer. */
    message = cJSON_Print(object);
    if (message == NULL) {
        goto Error;
    }

    cJSON_Delete(object);

    ocall_print("Sending GetDeviceTEEStateTBSResponse...\n");

    sgxStatus = ocall_SendOTrPMessage(&err, message, strlen(message));
    if (sgxStatus != SGX_SUCCESS) {
        return sgxStatus;
    }
    return err;

Error:
    cJSON_Delete(object);
    return 1; /* error */
}

int ecall_ProcessOTrPMessage(
    const char* message,
    int messageLength)
{
    int err = 1;
    cJSON* object = NULL;
    char *newstr = NULL;
    cJSON* messageObject = NULL;

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

    object = cJSON_Parse(str);
    if ((object == NULL) || !cJSON_IsObject(object)) {
        goto Done;
    }
    messageObject = object->child;
    if (!cJSON_IsObject(messageObject)) {
        goto Done;
    }

    ocall_print("Received ");
    ocall_print(messageObject->string);
    ocall_print("\n");

    if (strcmp(messageObject->string, "GetDeviceStateTBSRequest") == 0) {
        err = OTrPHandleGetDeviceStateRequest(messageObject);
    } else {
        /* Unrecognized message. */
        err = 1;
    }

Done:
    free(newstr);
    cJSON_Delete(object);
    return err;
}
