// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <windows.h>
#include "HttpClient.h"
#include "HttpHelper.h"
#include "TeepAgentLib.h"
#include "teep_protocol.h"
#include "HttpServer.h"
#include "TeepTamLib.h"

TeepAgentSession g_Session = { 0 };

// The caller is responsible for freeing the buffer if one is returned.
_Success_(return == NO_ERROR)
int
MakeHttpCall(
    _In_ PCSTR verb,
    _In_ PCSTR authority,
    _In_ PCSTR path,
    _In_opt_ PCSTR extraHeaders,
    _In_opt_ PCSTR data,
    size_t dataLength,
    _In_ PCSTR acceptType,
    _Out_ int* pStatusCode,
    _Out_ int* pContentLength,
    _Outptr_opt_result_nullonfailure_ char** pBuffer,
    _Outptr_opt_result_nullonfailure_ char** pMediaType)
{
    return ERROR_NOT_SUPPORTED;
}

// Send an empty POST to the indicated URI.
int Connect(const char* tamUri, const char* acceptMediaType)
{
    return ProcessConnect(&g_Session, acceptMediaType);
}

teep_error_code_t TeepAgentQueueOutboundTeepMessage(
    _In_ void* sessionHandle,
    _In_z_ const char* mediaType,
    _In_reads_(messageLength) const char* message,
    size_t messageLength)
{
    return (teep_error_code_t)TamProcessTeepMessage(
        sessionHandle,
        mediaType,
        message,
        messageLength);
}

// The caller is responsible for freeing the returned buffer if non-null.
const char* SendTeepMessage(TeepAgentSession* session, char** pResponseMediaType, int* pResponseLength)
{
    return nullptr;
}

int RunHttpServer(int argc, const wchar_t** argv)
{
    return ERROR_NOT_SUPPORTED;
}

teep_error_code_t TamQueueOutboundTeepMessage(void* sessionHandle, const char* mediaType, const char* message, size_t messageLength)
{
    return (teep_error_code_t)TeepAgentProcessTeepMessage(sessionHandle, mediaType, message, messageLength);
}