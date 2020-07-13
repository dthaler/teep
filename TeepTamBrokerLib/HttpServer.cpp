/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <http.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "HttpServer.h"
#include "../TeepTamBrokerLib/TeepTamBrokerLib.h"
#include "../TeepTamBrokerLib/TeepTam_u.h" // for OCALL prototypes

#pragma comment(lib, "httpapi.lib")

#define ASSERT(x) if (!(x)) { DebugBreak(); }

typedef struct {
    char MediaType[80];
    const char* OutboundMessage;
    size_t OutboundMessageLength;
} TeepSession;

TeepSession g_Session = { NULL, 0 };

int ocall_QueueOutboundTeepMessage(void* sessionHandle, const char* mediaType, const char* message, unsigned int messageLength)
{
    TeepSession* session = (TeepSession*)sessionHandle;

    assert(session->OutboundMessage == nullptr);

    // Save message for later transmission.
    char* data = (char*)malloc(messageLength);
    if (data == nullptr) {
        return 1;
    }
    memcpy(data, message, messageLength);
    session->OutboundMessage = data;
    session->OutboundMessageLength = messageLength;
    printf("Sending %d bytes...\n", messageLength);

    strcpy_s(session->MediaType, sizeof(session->MediaType), mediaType);
    return 0;
}

//
// Macros.
//
#define INITIALIZE_HTTP_RESPONSE( resp, status, reason )    \
    do                                                      \
    {                                                       \
        RtlZeroMemory( (resp), sizeof(*(resp)) );           \
        (resp)->StatusCode = (status);                      \
        (resp)->pReason = (reason);                         \
        (resp)->ReasonLength = (USHORT) strlen(reason);     \
    } while (FALSE)

#define ADD_KNOWN_HEADER(Response, HeaderId, RawValue)               \
    do                                                               \
    {                                                                \
        (Response).Headers.KnownHeaders[(HeaderId)].pRawValue =      \
                                                          (RawValue);\
        (Response).Headers.KnownHeaders[(HeaderId)].RawValueLength = \
            (USHORT) strlen(RawValue);                               \
    } while(FALSE)

#define ALLOC_MEM(cb) HeapAlloc(GetProcessHeap(), 0, (cb))
#define FREE_MEM(ptr) HeapFree(GetProcessHeap(), 0, (ptr))

#define MAX_ULONG_STR ((ULONG) sizeof("4294967295"))

// The following functions are based on code from https://docs.microsoft.com/en-us/windows/desktop/Http/http-server-sample-application

DWORD SendHttpResponse(
    _In_ HANDLE hReqQueue,
    _In_ HTTP_REQUEST* pRequest,
    USHORT StatusCode,
    _In_z_ PCSTR pReason,
    _In_opt_z_ PCSTR pContentType,
    _In_reads_opt_(EntityStringLength) PCSTR pEntityString,
     size_t EntityStringLength)
{
    HTTP_RESPONSE   response;
    HTTP_DATA_CHUNK dataChunk;
    DWORD           result;
    DWORD           bytesSent;

    if (EntityStringLength > ULONG_MAX) {
        return ERROR_INVALID_PARAMETER;
    }

    //
    // Initialize the HTTP response structure.
    //
    INITIALIZE_HTTP_RESPONSE(&response, StatusCode, pReason);

    //
    // Add a known header.
    //
    if (pContentType != NULL)
    {
        ADD_KNOWN_HEADER(response, HttpHeaderContentType, pContentType);
    }

    if (pEntityString)
    {
        //
        // Add an entity chunk.
        //
        dataChunk.DataChunkType = HttpDataChunkFromMemory;
        dataChunk.FromMemory.pBuffer = (void*)pEntityString;
        dataChunk.FromMemory.BufferLength = (ULONG)EntityStringLength;

        response.EntityChunkCount = 1;
        response.pEntityChunks = &dataChunk;
    }

    //
    // Because the entity body is sent in one call, it is not
    // required to specify the Content-Length.
    //

    result = HttpSendHttpResponse(
        hReqQueue,           // ReqQueueHandle
        pRequest->RequestId, // Request ID
        0,                   // Flags
        &response,           // HTTP response
        NULL,                // pReserved1
        &bytesSent,          // bytes sent  (OPTIONAL)
        NULL,                // pReserved2  (must be NULL)
        0,                   // Reserved3   (must be 0)
        NULL,                // LPOVERLAPPED(OPTIONAL)
        NULL                 // pReserved4  (must be NULL)
    );

    if (result != NO_ERROR)
    {
        wprintf(L"HttpSendHttpResponse failed with %lu\n", result);
    }

    return result;
}

// Handle an incoming POST request, which might be for any session.
DWORD HandleHttpPost(
    _In_ HANDLE        hReqQueue,
    _In_ HTTP_REQUEST* pRequest)
{
    TeepSession* session = &g_Session;
    int result = 0;

    // Allocate a buffer for the content.
    int inputBufferSize = 4096;
    char* inputBuffer = (PCHAR)ALLOC_MEM(inputBufferSize);
    if (inputBuffer == nullptr) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    int totalBytesRead = 0;

    // Read the entire body into a buffer.
    if (pRequest->Flags & HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS) {
        do {
            DWORD bytesRead = 0;
            result = HttpReceiveRequestEntityBody(
                hReqQueue,
                pRequest->RequestId,
                HTTP_RECEIVE_REQUEST_ENTITY_BODY_FLAG_FILL_BUFFER,
                inputBuffer + totalBytesRead,
                inputBufferSize - totalBytesRead,
                &bytesRead,
                NULL);

            if (result == NO_ERROR || result == ERROR_HANDLE_EOF) {
                totalBytesRead += bytesRead;
            }
        } while (result == NO_ERROR);
    }
    if (totalBytesRead < inputBufferSize) {
        inputBuffer[totalBytesRead] = 0; // Add null termination for debugging ease.
    }

    if (totalBytesRead == 0) {
        // A 0-byte post is a connect.
        FREE_MEM(inputBuffer);

        // Get the Accept header value, if any.
        HTTP_KNOWN_HEADER* acceptHeader = &pRequest->Headers.KnownHeaders[HttpHeaderAccept];
        int mediaTypeLength = acceptHeader->RawValueLength;
        char* mediaType = nullptr;
        if (mediaTypeLength > 0) {
            mediaType = new char[mediaTypeLength + 1];
            memcpy(mediaType, acceptHeader->pRawValue, mediaTypeLength);
            mediaType[mediaTypeLength] = 0;
        }

        int connectResult = TeepHandleConnect(session, mediaType);
        delete mediaType;
        if (connectResult != 0) {
            return SendHttpResponse(
                hReqQueue,
                pRequest,
                400,
                "Bad Request",
                nullptr,
                nullptr,
                0);
        }

        result = SendHttpResponse(
                hReqQueue,
                pRequest,
                200,
                "OK",
                session->MediaType,
                session->OutboundMessage,
                session->OutboundMessageLength);

        free((char*)session->OutboundMessage);
        session->OutboundMessage = nullptr;
        session->OutboundMessageLength = 0;

        return result;
    }

    // Get the Content-Type header value, if any.
    HTTP_KNOWN_HEADER* contentTypeHeader = &pRequest->Headers.KnownHeaders[HttpHeaderContentType];
    int mediaTypeLength = contentTypeHeader->RawValueLength;
    char* mediaType = nullptr;
    if (mediaTypeLength > 0) {
        mediaType = new char[mediaTypeLength + 1];
        memcpy(mediaType, contentTypeHeader->pRawValue, mediaTypeLength);
        mediaType[mediaTypeLength] = 0;
    }

    if (TeepHandleMessage(session, mediaType, inputBuffer, totalBytesRead) != 0) {
        result = SendHttpResponse(
            hReqQueue,
            pRequest,
            400,
            "Bad Request",
            nullptr,
            nullptr,
            0);
    } else {
        result = SendHttpResponse(
            hReqQueue,
            pRequest,
            200,
            "OK",
            session->MediaType,
            session->OutboundMessage,
            session->OutboundMessageLength);
    }

    delete mediaType;

    if (session->OutboundMessage != nullptr) {
        free((char*)session->OutboundMessage);
        session->OutboundMessage = nullptr;
        session->OutboundMessageLength = 0;
    }

    FREE_MEM(inputBuffer);
    return 0;
}

// Handle a series of incoming requests, which might be for different sessions.
DWORD DoReceiveRequests(
    _In_ HANDLE hReqQueue)
{
    ULONG              result;
    HTTP_REQUEST_ID    requestId;
    DWORD              totalBytesRead;
    PHTTP_REQUEST      pRequest;
    PCHAR              pRequestBuffer;
    ULONG              RequestBufferLength;
    char               responseBuffer[1024];
    const char        *pResponseString = responseBuffer;

    //
    // Allocate a 2 KB buffer. This size should work for most
    // requests. The buffer size can be increased if required. Space
    // is also required for an HTTP_REQUEST structure.
    //
    RequestBufferLength = sizeof(HTTP_REQUEST) + 2048;
    pRequestBuffer = (PCHAR)ALLOC_MEM(RequestBufferLength);

    if (pRequestBuffer == NULL)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    pRequest = (PHTTP_REQUEST)pRequestBuffer;

    //
    // Wait for a new request. This is indicated by a NULL
    // request ID.
    //

    HTTP_SET_NULL_ID(&requestId);

    for (;;)
    {
        RtlZeroMemory(pRequest, RequestBufferLength);

        result = HttpReceiveHttpRequest(
            hReqQueue,          // Req Queue
            requestId,          // Req ID
            0,                  // Flags
            pRequest,           // HTTP request buffer
            RequestBufferLength,// req buffer length
            &totalBytesRead,    // bytes received
            NULL);              // LPOVERLAPPED

        if (NO_ERROR == result)
        {
            TeepSession* session = &g_Session;

            //
            // Worked!
            //
            switch (pRequest->Verb)
            {
            case HttpVerbGET:
                wprintf(L"Got a GET request for %ws\n",
                    pRequest->CookedUrl.pFullUrl);

                if (wcscmp(pRequest->CookedUrl.pAbsPath, TEEP_PATH) == 0) {
                    // Get the Accept header value, if any.
                    HTTP_KNOWN_HEADER* acceptHeader = &pRequest->Headers.KnownHeaders[HttpHeaderAccept];
                    int mediaTypeLength = acceptHeader->RawValueLength;
                    char* mediaType = nullptr;
                    if (mediaTypeLength > 0) {
                        mediaType = new char[mediaTypeLength + 1];
                        memcpy(mediaType, acceptHeader->pRawValue, mediaTypeLength);
                        mediaType[mediaTypeLength] = 0;
                    }

                    int connectResult = TeepHandleConnect(session, mediaType);
                    delete mediaType;
                    if (connectResult != 0) {
                        break;
                    }

                    result = SendHttpResponse(
                        hReqQueue,
                        pRequest,
                        200,
                        "OK",
                        session->MediaType,
                        session->OutboundMessage,
                        session->OutboundMessageLength);

                    free((char*)session->OutboundMessage);
                    session->OutboundMessage = nullptr;
                } else {
                    pResponseString = "[{\"error\":1234}}]\r\n";

                    result = SendHttpResponse(
                        hReqQueue,
                        pRequest,
                        200,
                        "OK",
                        session->MediaType,
                        pResponseString,
                        strlen(pResponseString));
                }
                break;

            case HttpVerbPOST:
                wprintf(L"Got a POST request for %ws\n",
                    pRequest->CookedUrl.pFullUrl);

                if (wcscmp(pRequest->CookedUrl.pAbsPath, TEEP_PATH) == 0) {
                    result = HandleHttpPost(hReqQueue, pRequest);
                } else {
                    result = SendHttpResponse(
                        hReqQueue,
                        pRequest,
                        404,
                        "Not Found",
                        nullptr,
                        nullptr,
                        0);
                }
                break;
            default:
                wprintf(L"Got a unknown request for %ws\n",
                    pRequest->CookedUrl.pFullUrl);

                result = SendHttpResponse(
                    hReqQueue,
                    pRequest,
                    503,
                    "Not Implemented",
                    nullptr,
                    nullptr,
                    0);
                break;
            }

            if (result != NO_ERROR)
            {
                break;
            }

            //
            // Reset the Request ID to handle the next request.
            //
            HTTP_SET_NULL_ID(&requestId);
        }
        else if (result == ERROR_MORE_DATA)
        {
            //
            // The input buffer was too small to hold the request
            // headers. Increase the buffer size and call the
            // API again.
            //
            // When calling the API again, handle the request
            // that failed by passing a RequestID.
            //
            // This RequestID is read from the old buffer.
            //
            requestId = pRequest->RequestId;

            //
            // Free the old buffer and allocate a new buffer.
            //
            RequestBufferLength = totalBytesRead;
            FREE_MEM(pRequestBuffer);
            pRequestBuffer = (PCHAR)ALLOC_MEM(RequestBufferLength);

            if (pRequestBuffer == nullptr)
            {
                result = ERROR_NOT_ENOUGH_MEMORY;
                break;
            }

            pRequest = (PHTTP_REQUEST)pRequestBuffer;

        }
        else if (ERROR_CONNECTION_INVALID == result &&
            !HTTP_IS_NULL_ID(&requestId))
        {
            // The TCP connection was corrupted by the peer when
            // attempting to handle a request with more buffer.
            // Continue to the next request.

            HTTP_SET_NULL_ID(&requestId);
        }
        else
        {
            break;
        }

    }

    if (pRequestBuffer)
    {
        FREE_MEM(pRequestBuffer);
    }

    return result;
}

int RunHttpServer(int argc, const wchar_t** argv)
{
    ULONG           retCode;
    HANDLE          hReqQueue = nullptr;
    int             UrlAdded = 0;
    HTTPAPI_VERSION HttpApiVersion = HTTPAPI_VERSION_1;

    //
    // Initialize HTTP Server APIs
    //
    retCode = HttpInitialize(
        HttpApiVersion,
        HTTP_INITIALIZE_SERVER,    // Flags
        nullptr                    // Reserved
    );

    if (retCode != NO_ERROR)
    {
        wprintf(L"HttpInitialize failed with %lu\n", retCode);
        return retCode;
    }

    //
    // Create a Request Queue Handle
    //
    retCode = HttpCreateHttpHandle(
        &hReqQueue,        // Req Queue
        0                  // Reserved
    );

    if (retCode != NO_ERROR)
    {
        wprintf(L"HttpCreateHttpHandle failed with %lu\n", retCode);
        goto CleanUp;
    }

    //
    // The arguments represent URIs that to
    // listen on. Call HttpAddUrl for each URI.
    //
    // The URI is a fully qualified URI and must include the
    // terminating (/) character.
    //
    for (int i = 1; i < argc; i++)
    {
        wprintf(L"listening for requests on the following url: %ls\n", argv[i]);

        retCode = HttpAddUrl(
            hReqQueue,    // Req Queue
            argv[i],      // Fully qualified URL
            nullptr       // Reserved
        );

        if (retCode == ERROR_ACCESS_DENIED)
        {
            wprintf(L"The application does not have permission to register this URL, try running as Administrator.\n");
            goto CleanUp;
        }
        if (retCode != NO_ERROR)
        {
            wprintf(L"HttpAddUrl failed with error %lu\n", retCode);
            goto CleanUp;
        }
        else
        {
            //
            // Track the currently added URLs.
            //
            UrlAdded++;
        }
    }

    DoReceiveRequests(hReqQueue);

CleanUp:

    //
    // Call HttpRemoveUrl for all added URLs.
    //
    for (int i = 1; i <= UrlAdded; i++)
    {
        HttpRemoveUrl(
            hReqQueue,     // Req Queue
            argv[i]        // Fully qualified URL
        );
    }

    //
    // Close the Request Queue handle.
    //
    if (hReqQueue)
    {
        CloseHandle(hReqQueue);
    }

    //
    // Call HttpTerminate.
    //
    HttpTerminate(HTTP_INITIALIZE_SERVER, nullptr);

    return retCode;
}
