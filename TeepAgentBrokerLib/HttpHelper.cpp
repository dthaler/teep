// HttpHelper.cpp : implementation file
//
#include <windows.h>
#include <stdio.h>
#include <WinInet.h>
#include <IPTypes.h>
#include "HttpHelper.h"

#ifndef ASSERT
#ifdef _DEBUG
# define ASSERT(x) { if (!(x)) { DebugBreak(); } _Analysis_assume_(x); }
#else
# define ASSERT(x)
#endif
#endif

PCSTR ConvertToUtf8(_Out_writes_(cchBuffer) PSTR buffer, int cchBuffer, _In_ PCWSTR input)
{
    // TODO(P2): use UTF8 not ANSI.
    sprintf_s(buffer, cchBuffer, "%ls", input);
    return buffer;
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
    int dataLength,
    _In_ PCSTR acceptType,
    _Out_ int* pStatusCode,
    _Out_ int* pContentLength,
    _Outptr_opt_result_nullonfailure_ char** pBuffer,
    _Outptr_opt_result_nullonfailure_ char** pMediaType)
{
    PCSTR userAgent = ABT_USER_AGENT;

    int ret = NO_ERROR;
    if (pBuffer != nullptr) {
        *pBuffer = nullptr;
    }
    if (pMediaType != nullptr) {
        *pMediaType = nullptr;
    }
    *pContentLength = 0;

    HINTERNET hInternet = InternetOpenA(userAgent, INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    if (hInternet == nullptr) {
        ret = GetLastError();
        ASSERT(ret != NO_ERROR);
        return ret;
    }

    char hostname[MAX_DNS_SUFFIX_STRING_LENGTH], *p;
    USHORT port = INTERNET_DEFAULT_HTTP_PORT;
    strcpy_s(hostname, _countof(hostname), authority);
    p = strchr((PSTR)hostname, ':');
    if (p != nullptr) {
        port = (USHORT)atoi(p + 1);
        *p = 0;
    }

    HINTERNET hConnect = InternetConnectA(
        hInternet,
        hostname,
        port,
        nullptr,  // No username.
        nullptr,  // No password.
        INTERNET_SERVICE_HTTP,
        0,        // Flags.
        0);       // Context.
    if (hConnect == nullptr) {
        ret = GetLastError();
        ASSERT(ret != NO_ERROR);
        InternetCloseHandle(hInternet);
        return ret;
    }

    PCSTR acceptTypes[] = { acceptType, nullptr};
    HINTERNET hRequest = HttpOpenRequestA(
        hConnect,
        verb,
        path,
        nullptr,  // Default HTTP version.
        nullptr,  // No referer.
        acceptTypes,
        0,        // No flags,
        0);       // Empty context.
    if (hRequest == nullptr) {
        ret = GetLastError();
        ASSERT(ret != NO_ERROR);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return ret;
    }

    if (extraHeaders != nullptr) {
        if (!HttpAddRequestHeadersA(hRequest, extraHeaders, (DWORD)-1, 0)) {
            ret = GetLastError();
            ASSERT(ret != NO_ERROR);
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return ret;
        }
    }

    BOOL ok = HttpSendRequestA(
        hRequest,
        nullptr, // No additional headers.
        (DWORD)-1L, // Autocompute header length.
        (PVOID)data,
        dataLength);
    if (!ok) {
        ret = GetLastError();
        ASSERT(ret != NO_ERROR);
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return ret;
    }

    CHAR responseText[256] = "";
    DWORD responseTextSize = sizeof(responseText);
    DWORD index = 0;
    ok = HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE, &responseText, &responseTextSize, &index);
    if (!ok) {
        ret = GetLastError();
        ASSERT(ret != NO_ERROR);
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return ret;
    }
    *pStatusCode = atoi(responseText);

    // Reset the max response text size so we can get the full content length.
    responseTextSize = sizeof(responseText);
    index = 0;
    ok = HttpQueryInfoA(hRequest, HTTP_QUERY_CONTENT_LENGTH, &responseText, &responseTextSize, &index);
    if (!ok) {
        *pContentLength = 65536; // Default maximum size of response.
    } else {
        *pContentLength = atoi(responseText);
    }

    if (pMediaType != nullptr) {
        CHAR mediaType[256] = "";
        DWORD mediaTypeSize = sizeof(mediaType);
        index = 0;
        ok = HttpQueryInfoA(hRequest, HTTP_QUERY_CONTENT_TYPE, &mediaType, &mediaTypeSize, &index);
        if (ok) {
            CHAR* mediaTypeBuffer = new char[mediaTypeSize + 1];
            strcpy_s(mediaTypeBuffer, mediaTypeSize + 1, mediaType);
            *pMediaType = mediaTypeBuffer;
        }
    }

    CHAR* temp = new char[*pContentLength + 1];
    ULONG bytesRead;
    ULONG bytesLeft = *pContentLength;
    if (pBuffer != nullptr) {
        *pBuffer = temp;
    }
    while ((bytesLeft > 0) && InternetReadFile(hRequest, temp, bytesLeft, &bytesRead) && (bytesRead > 0)) {
        temp += bytesRead;
        bytesLeft -= bytesRead;
    }
    *temp = '\0';    // manually append NULL terminator

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return NO_ERROR;
}

#if 0
_Success_(return == 0)
int
MakeHttpJsonCall(
    _In_ PCSTR verb,
    _In_ PCSTR authority,
    _In_ PCSTR path,
    _In_opt_ PCSTR data,
    _Out_ int* pStatusCode,
    _Outptr_opt_result_nullonfailure_ json_t** result)
{
    if (result != nullptr) {
        *result = nullptr;
    }

    PCSTR extraHeaders = (data != NULL) ? "Content-type: application/json\r\n" : NULL;

    char* buffer;
    int ret = MakeHttpCall(verb, authority, path, extraHeaders, data, "application/json", pStatusCode, &buffer);
    if (ret != 0) {
        return ret;
    }

    if ((*pStatusCode < 200) || (*pStatusCode >= 300)) {
        delete [] buffer;
        return 1;
    }

    if (result == nullptr) {
        delete [] buffer;
        return 0;
    }

    char* end = buffer + strlen(buffer);
    JsonAuto val = new Json::Value();

    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    Json::CharReader* reader = builder.newCharReader();
    std::string errs;
    bool ok = reader->parse(buffer, end, val, &errs);
    delete [] buffer;
    delete reader;
    if (!ok) {
        // Invalid JSON passed to JSON parser.
        return 1;
    }
    if (val->isObject()) {
        Json::Value* obj = val;
        if (obj->isMember("error")) {
            PCSTR errorMessage = (*obj)["error"].asCString();
            printf("Error %s\n", errorMessage);
            delete obj;
            return 1;
        }
    }

    *result = val;
    return 0;
}

_Success_(return == 0)
int
MakeHttpGet(
    _In_ PCWSTR authority,
    _In_ PCSTR path,
    _Out_ int* pStatusCode,
    _Outptr_result_nullonfailure_ json_t** result)
{
    CHAR authorityA[256];
    sprintf_s(authorityA, _countof(authorityA), "%ls", authority);
    return MakeHttpJsonCall("GET", authorityA, path, nullptr, pStatusCode, result);
}

_Success_(return == 0)
int
MakeHttpPost(
    _In_ PCWSTR authority,
    _In_ PCSTR path,
    _In_opt_ const json_t* content,
    _Out_ int* pStatusCode,
    _Outptr_opt_result_nullonfailure_ json_t** result)
{
    PCSTR data = nullptr;
    std::ostringstream stream;
    std::string str;
    if (content != nullptr) {
        Json::StreamWriterBuilder builder;
        builder["commentStyle"] = "None";
#ifdef _DEBUG
        builder["indentation"] = "   ";
#endif
        Json::StreamWriter* writer = builder.newStreamWriter();
        writer->write(*content, &stream);
        delete writer;
        str = stream.str();
        data = str.c_str();
    }

    CHAR authorityA[256];
    sprintf_s(authorityA, _countof(authorityA), "%ls", authority);
    return MakeHttpJsonCall("POST", authorityA, path, data, pStatusCode, result);
}
#endif