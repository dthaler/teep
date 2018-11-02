/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdlib.h>
#include <string.h>
#include "../cJSON/cJSON.h"
#include "OTrPTam_t.h"

int ecall_ProcessOTrPConnect(void)
{
    char* message = NULL;
    size_t messageLength = 0;
    cJSON* object = NULL;
    cJSON* request = NULL;
    cJSON* ocspdat = NULL;
    cJSON* supportedsigalgs = NULL;
    int err = 0;
    sgx_status_t sgxStatus = SGX_SUCCESS;

    ocall_print("Received client connection\n");

    /* Compose a GetDeviceStateRequest message. */
    object = cJSON_CreateObject();
    if (object == NULL) {
        goto Error;
    }
    request = cJSON_AddObjectToObject(object, "GetDeviceStateTBSRequest");
    if (request == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(request, "ver", "1.0") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(request, "rid", "<Unique request ID>") == NULL) {
        goto Error;
    }
    if (cJSON_AddStringToObject(request, "tid", "<transaction ID>") == NULL) {
        goto Error;
    }
    ocspdat = cJSON_AddArrayToObject(request, "ocspdat");
    if (ocspdat == NULL) {
        goto Error;
    }
    /* TODO: Fill in list of OCSP stapling data. */

    /* supportedsigalgs is optional, so omit for now. */

    /* Convert to message buffer. */
    message = cJSON_Print(object);
    if (message == NULL) {
        goto Error;
    }
    messageLength = strlen(message);

    ocall_print("Sending GetDeviceStateTBSRequest...\n");

    sgxStatus = ocall_SendOTrPMessage(&err, message, messageLength);
    if (sgxStatus != SGX_SUCCESS) {
        goto Error;
    }

    cJSON_Delete(object);
    return err;

Error:
    cJSON_Delete(object);
    return 1; /* error */
}

int OTrPHandleGetDeviceStateResponse(cJSON* messageObject)
{
    return 0; /* no error */
}

int OTrPHandleTADependencyNotification(cJSON* messageObject)
{
    return 0; /* no error */
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
    }
    else {
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

    if (strcmp(messageObject->string, "GetDeviceTEEStateTBSResponse") == 0) {
        err = OTrPHandleGetDeviceStateResponse(messageObject);
    } else if (strcmp(messageObject->string, "TADependencyTBSNotification") == 0) {
        err = OTrPHandleTADependencyNotification(messageObject);
    } else {
        /* Unrecognized message. */
        err = 1;
    }

Done:
    free(newstr);
    cJSON_Delete(object);
    return err;
}