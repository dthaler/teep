/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <Windows.h>
#include <wininet.h>
#include <assert.h>
#include <string.h>
extern "C" {
#include "HttpHelper.h"
#include "HttpClient.h"
#include "OTrPSession.h"
#include "../OTrPAgentBrokerLib/OTrPAgent_u.h"
#include "../OTrPAgentBrokerLib/OTrPAgentBrokerLib.h"
};

#define OTRP_JSON_MEDIA_TYPE "application/otrp+json"

OTrPSession g_Session = { NULL };

// Send a GET to the indicated URI.
int ocall_Connect(const char* tamUri)
{
    char authority[266];
    char hostName[256];
    char path[256];
    int statusCode;
    char* responseBuffer;
    URL_COMPONENTS components = { sizeof(components) };

    // Get authority and path from URI.
    components.dwHostNameLength = 255;
    components.lpszHostName = hostName;
    components.dwUrlPathLength = 255;
    components.lpszUrlPath = path;
    if (!InternetCrackUrl(tamUri, 0, 0, &components)) {
        return GetLastError();
    }
    sprintf_s(authority, sizeof(authority), "%s:%d", components.lpszHostName, components.nPort);

    // Create session state.
    OTrPSession* session = &g_Session;
    strcpy_s(session->TamUri, tamUri);

    int err = MakeHttpCall(
        "GET",
        authority,
        path,
        NULL,
        NULL,
        OTRP_JSON_MEDIA_TYPE,
        &statusCode,
        &responseBuffer);
    if (err != 0) {
        return err;
    }
    if (statusCode != 200) {
        return statusCode;
    }

    assert(session->ResponseBuffer == nullptr);
    session->ResponseBuffer = responseBuffer;

    return 0;
}

int ocall_SendOTrPMessage(void* sessionHandle, const char* message)
{
    OTrPSession* session = (OTrPSession*)sessionHandle;

    size_t messageLength = strlen(message);
    assert(session->MessageToSend == NULL);

    // Save message for later transmission.
    session->MessageToSend = _strdup(message);
    return (session->MessageToSend == NULL);
}

const char* HandleHttpResponse(void* sessionHandle, const char* message)
{
    OTrPSession* session = (OTrPSession*)sessionHandle;
    int len = strlen(message);
    int err = OTrPHandleMessage(sessionHandle, message, strlen(message));

    free((char*)message);

    if (err != 0) {
        printf("Error %d\n", err);
        return NULL;
    }

    const char* authority = session->TamUri; // TODO
    const char* path = "/";
    PCSTR extraHeaders = "Content-type: " OTRP_JSON_MEDIA_TYPE "\r\n";
    int statusCode;
    char* responseBuffer;

    err = MakeHttpCall(
        "PUT",
        authority,
        path,
        extraHeaders,
        session->MessageToSend,
        OTRP_JSON_MEDIA_TYPE,
        &statusCode,
        &responseBuffer);

    if (session->MessageToSend != NULL) {
        free((char*)session->MessageToSend);
        session->MessageToSend = NULL;
    }

    if (err != 0) {
        return NULL;
    }
    if (statusCode != 200) {
        return NULL;
    }
    return responseBuffer;
}
