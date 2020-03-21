/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <Windows.h>
#include <wininet.h>
#include <assert.h>
#include <string.h>
extern "C" {
#include "TeepSession.h"
#include "HttpHelper.h"
#include "HttpClient.h"
#include "TeepAgent_u.h"
#include "TeepAgentBrokerLib.h"
};

TeepSession g_Session = { 0 };

// Send an empty POST to the indicated URI.
int ocall_Connect(const char* tamUri, const char* mediaType)
{
    char authority[266];
    char hostName[256];
    char path[256];
    int statusCode;
    char* responseBuffer;
    char* responseMediaTypeBuffer;
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
    TeepSession* session = &g_Session;
    strcpy_s(session->TamUri, tamUri);

    int err = MakeHttpCall(
        "POST",
        authority,
        path,
        nullptr,
        nullptr,
        mediaType,
        &statusCode,
        &responseBuffer,
        &responseMediaTypeBuffer);
    if (err != 0) {
        return err;
    }
    if (statusCode != 200) {
        return statusCode;
    }

    assert(session->InboundMessage == nullptr);
    session->InboundMessage = responseBuffer;
    if (responseMediaTypeBuffer != nullptr) {
        strcpy_s(session->InboundMediaType, sizeof(session->InboundMediaType), responseMediaTypeBuffer);
    }

    return 0;
}

int ocall_QueueOutboundTeepMessage(void* sessionHandle, const char* mediaType, const char* message)
{
    TeepSession* session = (TeepSession*)sessionHandle;

    size_t messageLength = strlen(message);
    assert(session->OutboundMessage == nullptr);

    strcpy_s(session->OutboundMediaType, sizeof(session->OutboundMediaType), mediaType);

    // Save message for later transmission after the ECALL returns.
    session->OutboundMessage = _strdup(message);
    return (session->OutboundMessage == nullptr);
}

// The caller is responsible for freeing the returned buffer if non-null.
const char* SendTeepMessage(TeepSession* session, char** pResponseMediaType)
{
    char authority[266];
    char hostName[256];
    char path[256];
    int statusCode;
    char* responseBuffer;
    URL_COMPONENTS components = { sizeof(components) };
    char extraHeaders[256];

    // Get authority and path from URI.
    components.dwHostNameLength = 255;
    components.lpszHostName = hostName;
    components.dwUrlPathLength = 255;
    components.lpszUrlPath = path;
    if (!InternetCrackUrl(session->TamUri, 0, 0, &components)) {
        return nullptr;
    }
    sprintf_s(authority, sizeof(authority), "%s:%d", components.lpszHostName, components.nPort);
    sprintf_s(extraHeaders, sizeof(extraHeaders),
        "Content-type: %s\r\n",
        session->OutboundMediaType);

    int err = MakeHttpCall(
        "POST",
        authority,
        path,
        extraHeaders,
        session->OutboundMessage,
        session->OutboundMediaType,
        &statusCode,
        &responseBuffer,
        pResponseMediaType);

    if (session->OutboundMessage != nullptr) {
        free((char*)session->OutboundMessage);
        session->OutboundMessage = nullptr;
    }

    if (err != 0) {
        return nullptr;
    }
    if (statusCode != 200) {
        return nullptr;
    }
    return responseBuffer;
}
