/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <string.h>
#include "OTrPTamLib.h"
#include "../cJSON/cJSON.h"

/* The caller must free the returned message with free(). */
int OTrPHandleClientConnect(char** pMessage, int* pMessageLength)
{
    char* message;
    cJSON* object = NULL;
    cJSON* request = NULL;
    cJSON* ocspdat = NULL;
    cJSON* supportedsigalgs = NULL;

    *pMessage = NULL;
    *pMessageLength = 0;

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

    cJSON_Delete(object);

    *pMessage = message;
    *pMessageLength = strlen(message);
    return 0; /* no error */

Error:
    if (object != NULL) {
        cJSON_Delete(object);
    }
    return 1; /* error */
}

int OTrPHandleClientMessage(
    const char *inputMessage,
    int inputMessageLength,
    char** pOutputMessage,
    int* pOutputMessageLength)
{
    return 1; /* error */
}
