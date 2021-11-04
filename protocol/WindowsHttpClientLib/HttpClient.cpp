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
};
#include "TeepAgentBrokerLib.h"

TeepAgentSession g_Session = { 0 };

// Send an empty POST to the indicated URI.
int TeepAgentConnect(_In_z_ const char* tamUri, _In_z_ const char* acceptMediaType)
{
    char authority[266];
    char hostName[256];
    char path[256];
    int statusCode;
    char* responseBuffer;
    char* responseMediaTypeBuffer;
    URL_COMPONENTSA components = { sizeof(components) };

    // Get authority and path from URI.
    components.dwHostNameLength = 255;
    components.lpszHostName = hostName;
    components.dwUrlPathLength = 255;
    components.lpszUrlPath = path;
    if (!InternetCrackUrlA(tamUri, 0, 0, &components)) {
        return GetLastError();
    }
    sprintf_s(authority, sizeof(authority), "%s:%d", components.lpszHostName, components.nPort);

    // Create session state.
    TeepAgentSession* session = &g_Session;
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

teep_error_code_t TeepAgentQueueOutboundTeepMessage(
    _In_ void* sessionHandle,
    _In_z_ const char* mediaType,
    _In_reads_(messageLength) const char* message,
    size_t messageLength)
{
    TeepBasicSession* session = (TeepBasicSession*)sessionHandle;

    assert(session->OutboundMessage == nullptr);

    strcpy_s(session->OutboundMediaType, sizeof(session->OutboundMediaType), mediaType);

    // Save message for later transmission after the ECALL returns.
    char* data = (char*)malloc(messageLength);
    if (data == nullptr) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    memcpy(data, message, messageLength);
    session->OutboundMessage = data;
    session->OutboundMessageLength = messageLength;
    printf("Sending %zd bytes...\n", messageLength);
    return TEEP_ERR_SUCCESS;
}

// The caller is responsible for freeing the returned buffer if non-null.
const char* TeepAgentSendMessage(TeepAgentSession* session, char** pResponseMediaType, int* pResponseLength)
{
    char authority[266];
    char hostName[256];
    char path[256];
    int statusCode;
    char* responseBuffer;
    URL_COMPONENTSA components = { sizeof(components) };
    char extraHeaders[256];

    // Get authority and path from URI.
    components.dwHostNameLength = 255;
    components.lpszHostName = hostName;
    components.dwUrlPathLength = 255;
    components.lpszUrlPath = path;
    if (!InternetCrackUrlA(session->TamUri, 0, 0, &components)) {
        return nullptr;
    }
    sprintf_s(authority, sizeof(authority), "%s:%d", components.lpszHostName, components.nPort);
    sprintf_s(extraHeaders, sizeof(extraHeaders),
        "Content-type: %s\r\n",
        session->Basic.OutboundMediaType);

    int err = MakeHttpCall(
        "POST",
        authority,
        path,
        extraHeaders,
        session->Basic.OutboundMessage,
        session->Basic.OutboundMessageLength,
        session->Basic.OutboundMediaType,
        &statusCode,
        pResponseLength,
        &responseBuffer,
        pResponseMediaType);

    if (session->Basic.OutboundMessage != nullptr) {
        free((char*)session->Basic.OutboundMessage);
        session->Basic.OutboundMessage = nullptr;
    }

    if (err != 0) {
        return nullptr;
    }
    if (statusCode != 200) {
        return nullptr;
    }
    return responseBuffer;
}
