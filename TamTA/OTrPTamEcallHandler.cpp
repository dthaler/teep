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
    extern char* strdup(const char* str);
};
#include "../jansson/JsonAuto.h"

void ecall_Initialize()
{
    // jose_init_ec();
    jose_init_rsa();
    // jose_init_oct();
}

/* Compose a GetDeviceStateRequest message. */
const char* ComposeGetDeviceStateRequest(void)
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
    return 0; /* no error */
}

int OTrPHandleTADependencyNotification(const json_t* messageObject)
{
    return 0; /* no error */
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

    if (strcmp(key, "GetDeviceTEEStateTBSResponse") == 0) {
        err = OTrPHandleGetDeviceStateResponse(messageObject);
    } else if (strcmp(key, "TADependencyTBSNotification") == 0) {
        err = OTrPHandleTADependencyNotification(messageObject);
    } else {
        /* Unrecognized message. */
        err = 1;
    }

    return err;
}