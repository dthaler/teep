/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <Windows.h>
#include <assert.h>
#include <string.h>
extern "C" {
#include "HttpHelper.h"
#include "HttpClient.h"
#include "..\DeviceLib\OTrPDevice_u.h"
#include "..\DeviceLib\OTrPDeviceLib.h"
};

#define JSON_MEDIA_TYPE "application/json"

// Send a GET to the indicated URI.
const char* ConnectToTam(const char* uri)
{
    const char* authority = uri; // TODO
    const char* path = "/OTRP"; // TODO
    int statusCode;
    char* responseBuffer;

    int err = MakeHttpCall(
        "GET",
        authority,
        path,
        NULL,
        NULL,
        JSON_MEDIA_TYPE,
        &statusCode,
        &responseBuffer);
    if (err != 0) {
        return NULL;
    }
    if (statusCode != 200) {
        return NULL;
    }
    return responseBuffer;
}

const char* g_MessageToSend = NULL;

int ocall_SendOTrPMessage(const char* message)
{
    size_t messageLength = strlen(message);
    assert(g_MessageToSend == NULL);

    // Save message for later transmission.
    g_MessageToSend = _strdup(message);
    return (g_MessageToSend == NULL);
}

const char* HandleHttpResponse(const char* message, const char* uri)
{
    int len = strlen(message);
    int err = OTrPHandleMessage(message, strlen(message));

    free((char*)message);

    if (err != 0) {
        printf("Error %d\n", err);
        return NULL;
    }

    const char* authority = uri; // TODO
    const char* path = "/";
    PCSTR extraHeaders = "Content-type: " JSON_MEDIA_TYPE "\r\n";
    int statusCode;
    char* responseBuffer;

    err = MakeHttpCall(
        "PUT",
        authority,
        path,
        extraHeaders,
        g_MessageToSend,
        JSON_MEDIA_TYPE,
        &statusCode,
        &responseBuffer);

    if (g_MessageToSend != NULL) {
        free((char*)g_MessageToSend);
        g_MessageToSend = NULL;
    }

    if (err != 0) {
        return NULL;
    }
    if (statusCode != 200) {
        return NULL;
    }
    return responseBuffer;
}
