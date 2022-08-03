// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#define ABT_USER_AGENT "TEEP Test"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WININET_RESOLVING_NAME        = 10,
    WININET_NAME_RESOLVED         = 11,
    WININET_CONNECTING_TO_SERVER  = 20,
    WININET_CONNECTED_TO_SERVER   = 21,
    WININET_SENDING_REQUEST       = 30,
    WININET_REQUEST_SENT          = 31,
    WININET_RECEIVING_RESPONSE    = 40,
    WININET_RESPONSE_RECEIVED     = 41,
    WININET_CTL_RESPONSE_RECEIVED = 42,
    WININET_PREFETCH              = 43,
    WININET_CLOSING_CONNECTION    = 50,
    WININET_CONNECTION_CLOSED     = 51,
    WININET_HANDLE_CREATED        = 60,
    WININET_HANDLE_CLOSING        = 70,
    WININET_DETECTING_PROXY       = 80,
    WININET_REQUEST_COMPLETE      = 100,
    WININET_REDIRECT              = 110,
    WININET_INTERMEDIATE_RESPONSE = 120,
    WININET_USER_INPUT_REQUIRED   = 140,
    WININET_STATE_CHANGE          = 200,
    WININET_COOKIE_SENT           = 320,
    WININET_COOKIE_RECEIVED       = 321,
    WININET_PRIVACY_IMPACTED      = 324,
    WININET_P3P_HEADER            = 325,
    WININET_P3P_POLICYREF         = 326,
    WININET_COOKIE_HISTORY        = 327,
} WininetStatus;

typedef enum
{
    HCS_IDLE = 0,   // Completes when a change is ready to be sent.
    HCS_CONNECTING,
    HCS_OPENING,
    HCS_SENDING,
} HttpChangeStage;

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
    _Outptr_opt_result_nullonfailure_ char** pBuffer = nullptr,
    _Outptr_opt_result_nullonfailure_ char** pMediaType = nullptr);

#ifdef __cplusplus
};
#endif
