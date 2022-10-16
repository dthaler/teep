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

// If this hits zero, send a ProcessError notification to the agent.
static int g_TransportErrorSchedule = INT_MAX;

void ScheduleTransportError(int count)
{
    g_TransportErrorSchedule = count;
}

uint64_t GetOutboundMessagesSent()
{
    return g_Session.Basic.OutboundMessagesSent;
}

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
teep_error_code_t TeepAgentConnect(_In_z_ const char* tamUri, _In_z_ const char* acceptMediaType)
{
    // Check for error injection.
    g_TransportErrorSchedule--;
    if (g_TransportErrorSchedule == 0) {
        return TeepAgentProcessError(&g_Session);
    }

    return TamProcessConnect(&g_Session, acceptMediaType);
}

teep_error_code_t TeepAgentQueueOutboundTeepMessage(
    _In_ void* sessionHandle,
    _In_z_ const char* mediaType,
    _In_reads_(messageLength) const char* message,
    size_t messageLength)
{
    g_Session.Basic.OutboundMessagesSent++;

    // Check for error injection.
    g_TransportErrorSchedule--;
    if (g_TransportErrorSchedule == 0) {
        return TeepAgentProcessError(&g_Session);
    }

    return TamProcessTeepMessage(
        sessionHandle,
        mediaType,
        message,
        messageLength);
}

// The caller is responsible for freeing the returned buffer if non-null.
const char* TeepAgentSendMessage(TeepAgentSession* session, char** pResponseMediaType, int* pResponseLength)
{
    return nullptr;
}

int RunHttpServer(int argc, const wchar_t** argv)
{
    return ERROR_NOT_SUPPORTED;
}

teep_error_code_t TamQueueOutboundTeepMessage(void* sessionHandle, const char* mediaType, const char* message, size_t messageLength)
{
    g_Session.Basic.OutboundMessagesSent++;

    // Check for error injection.
    g_TransportErrorSchedule--;
    if (g_TransportErrorSchedule == 0) {
        return TeepAgentProcessError(&g_Session);
    }

    return TeepAgentProcessTeepMessage(sessionHandle, mediaType, message, messageLength);
}