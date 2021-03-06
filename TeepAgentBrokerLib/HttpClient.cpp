// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
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
int ocall_Connect(const char* tamUri, const char* acceptMediaType)
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

    int responseLength;
    int err = MakeHttpCall(
        "POST",
        authority,
        path,
        nullptr,
        nullptr,
        0,
        acceptMediaType,
        &statusCode,
        &responseLength,
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
    session->InboundMessageLength = responseLength;
    if (responseMediaTypeBuffer != nullptr) {
        strcpy_s(session->InboundMediaType, sizeof(session->InboundMediaType), responseMediaTypeBuffer);
    }

    return 0;
}

int ocall_QueueOutboundTeepMessage(void* sessionHandle, const char* mediaType, const char* message, unsigned int messageLength)
{
    TeepSession* session = (TeepSession*)sessionHandle;

    assert(session->OutboundMessage == nullptr);

    strcpy_s(session->OutboundMediaType, sizeof(session->OutboundMediaType), mediaType);

    // Save message for later transmission after the ECALL returns.
    char* data = (char*)malloc(messageLength);
    if (data == nullptr) {
        return 1;
    }
    memcpy(data, message, messageLength);
    session->OutboundMessage = data;
    session->OutboundMessageLength = messageLength;
    printf("Sending %d bytes...\n", messageLength);
    return 0;
}

// The caller is responsible for freeing the returned buffer if non-null.
const char* SendTeepMessage(TeepSession* session, char** pResponseMediaType, int* pResponseLength)
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
        session->OutboundMessageLength,
        session->OutboundMediaType,
        &statusCode,
        pResponseLength,
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
