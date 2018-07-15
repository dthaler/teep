/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdlib.h>
#include <string.h>
#include "OTrPDevice_t.h"
#include "sgx_trts.h"
#include "../cJSON/cJSON.h"

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

    sgxStatus = ocall_SendOTrPMessage(&err, message, strlen(message));
    if (sgxStatus != SGX_SUCCESS) {
        return sgxStatus;
    }
    return 0; /* no error */

Error:
    if (object != NULL) {
        cJSON_Delete(object);
    }
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
    if (strcmp(messageObject->string, "GetDeviceStateTBSRequest") == 0) {
        err = OTrPHandleGetDeviceStateRequest(messageObject);
    }

Done:
    if (newstr != NULL) {
        free(newstr);
    }
    if (object != NULL) {
        cJSON_Delete(object);
    }
    return err;
}
