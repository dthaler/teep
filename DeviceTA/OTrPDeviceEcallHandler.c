/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdlib.h>
#include <string.h>
#include "OTrPDevice_t.h"
#include "sgx_trts.h"
#include "../cJSON/cJSON.h"

/* Compose a DeviceStateInformation message. */
const char* ComposeDeviceStateInformation(void)
{
    cJSON* object = cJSON_CreateObject();
    if (object == NULL) {
        goto Error;
    }
    cJSON* dsi = cJSON_AddObjectToObject(object, "dsi");
    if (dsi == NULL) {
        goto Error;
    }

    /* Add tfwdata. */
    cJSON* tfwdata = cJSON_AddObjectToObject(dsi, "tfwdata");
    if (tfwdata == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(tfwdata, "tbs", "<TFW to be signed data is the tid>") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(tfwdata, "cert", "<BASE64 encoded TFW certificate>") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(tfwdata, "sigalg", "Signing method") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(tfwdata, "sig", "<TFW signed data, BASE64 encoded>") == NULL) {
        goto Error;
    }

    /* Add tee. */
    cJSON* tee = cJSON_AddObjectToObject(dsi, "tee");
    if (tee == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(tee, "name", "<TEE name>") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(tee, "ver", "<TEE version>") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(tee, "cert", "<BASE64 encoded TEE cert>") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(tee, "cacert", "<JSON array value of CA certificates up to the root CA>") == NULL) {
        goto Error;
    }

    // sdlist is optional, so we omit it.

    cJSON* teeaiklist = cJSON_AddArrayToObject(tee, "teeaiklist");
    if (teeaiklist == NULL) {
        goto Error;
    }
    cJSON* teeaik = cJSON_CreateObject();
    if (teeaik == NULL) {
        goto Error;
    }
    cJSON_AddItemToArray(teeaiklist, teeaik);
    if (cJSON_AddStringToObject(teeaik, "spaik", "<SP AIK public key, BASE64 encoded>") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(teeaik, "spaiktype", "RSA") == NULL) { // RSA or ECC
        goto Error;
    }
    if (cJSON_AddStringToObject(teeaik, "spid", "<sp id>") == NULL) {
        goto Error;
    }

    cJSON* talist = cJSON_AddArrayToObject(tee, "talist");
    if (talist == NULL) {
        goto Error;
    }
    cJSON* ta = cJSON_CreateObject();
    if (ta == NULL) {
        goto Error;
    }
    cJSON_AddItemToArray(talist, ta);
    if (cJSON_AddStringToObject(ta, "taid", "<TA application identifier>") == NULL) {
        goto Error;
    }
    // taname is optional

    /* Convert to message buffer. */
    const char* message = cJSON_Print(object);
    if (message == NULL) {
        goto Error;
    }
    cJSON_Delete(object);
    return message;

Error:
    cJSON_Delete(object);
    return NULL;
}

/* Compose a TADependencyNotification message. */
const char* ComposeTADependencyTBSNotification(void)
{
    const char* dsi = ComposeDeviceStateInformation();
    if (dsi == NULL) {
        return NULL;
    }

    cJSON* object = cJSON_CreateObject();
    if (object == NULL) {
        goto Error;
    }
    cJSON* request = cJSON_AddObjectToObject(object, "TADependencyTBSNotification");
    if (request == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(request, "ver", "1.0") == NULL) {
        goto Error;
    }

    /* Signerreq should be true if the TAM should send its signer certificate and
    * OCSP data again in the subsequent messages.  The value may be
    * false if the device caches the TAM's signer certificate and OCSP
    * status.
    */
    if (cJSON_AddStringToObject(request, "signerreq", "true") == NULL) {
        goto Error;
    }
    cJSON* edsi = cJSON_AddObjectToObject(request, "edsi");
    if (edsi == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(edsi, "protected", "<BASE64URL encoding of encryption algorithm header JSON data>") == NULL) {
        goto Error;
    }
    cJSON* recipients = cJSON_AddArrayToObject(edsi, "recipients");
    if (recipients == NULL) {
        goto Error;
    }
    cJSON* recipient = cJSON_CreateObject();
    if (recipient == NULL) {
        goto Error;
    }
    cJSON_AddItemToArray(recipients, recipient);
    if (edsi == NULL) {
        goto Error;
    }
    cJSON* edsi_header = cJSON_AddObjectToObject(recipient, "header");
    if (edsi == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(edsi_header, "alg", "RSA1_5") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(recipient, "encrypted_key", "<encrypted value of CEK>") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(edsi, "iv", "<BASE64URL encoded IV data>") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(edsi, "ciphertext", "<Encrypted data over the JSON object of dsi (BASE64URL)>") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(edsi, "tag", "<JWE authentication tag (BASE64URL)>") == NULL) {
        goto Error;
    }

    /* Convert to message buffer. */
    const char* message = cJSON_Print(object);
    if (message == NULL) {
        goto Error;
    }
    cJSON_Delete(object);
    cJSON_free(dsi);
    return message;

Error:
    cJSON_Delete(object);
    cJSON_free(dsi);
    return NULL;
}

int ecall_ProcessOTrPConnect(void)
{
    char* message = NULL;
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
        newstr = malloc(messageLength + 1);
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
