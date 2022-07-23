// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "Interop.h"
#include <vcclr.h>
using namespace TamCsOverCppShim;
using namespace System;

TeepAgentSession g_AgentSession;

TamSession::TamSession() {}
TamSession::~TamSession() {}

// See https://stackoverflow.com/questions/186477/in-c-cli-how-do-i-declare-and-call-a-function-with-an-out-parameter
// for how output args work.
int TamSession::ProcessConnect(
    System::String^ acceptMediaType,
    [Out] array<System::Byte>^% outboundMessage,
    [Out] System::String^% outboundMediaType)
{
    TeepBasicSession& session = g_AgentSession.Basic;
    pin_ptr<const wchar_t> acceptMediaTypeW = PtrToStringChars(acceptMediaType);
    char acceptMediaTypeA[256];
    sprintf_s(acceptMediaTypeA, sizeof(acceptMediaTypeA), "%ls", acceptMediaTypeW);
    int result = TamProcessConnect(&g_AgentSession, acceptMediaTypeA);

    outboundMediaType = gcnew System::String(session.OutboundMediaType);

    // Copy the unmanaged buffer to a managed buffer.
    int length = (int)session.OutboundMessageLength;
    outboundMessage = gcnew array<System::Byte>(length);
    Marshal::Copy(IntPtr((unsigned char*)session.OutboundMessage), outboundMessage, 0, length);

    free((char*)session.OutboundMessage);
    session.OutboundMessage = nullptr;
    session.OutboundMessageLength = 0;

    return result;
}

ManagedType::ManagedType() {}
ManagedType::~ManagedType() {}

int ManagedType::TamBrokerStart(System::String^ manifestDirectory, bool simulatedTee)
{
#if 0
    pin_ptr<const wchar_t> manifestDirectoryW = PtrToStringChars(manifestDirectory);
    char manifestDirectoryA[256];
    sprintf_s(manifestDirectoryA, sizeof(manifestDirectoryA), "%ls", manifestDirectoryW);
    return StartTamBroker(manifestDirectoryA, (int)simulatedTee);
#else
    return 0;
#endif
}

int ManagedType::TamBrokerProcess(System::String^ tamUri)
{
#if 0
    pin_ptr<const wchar_t> tamUriW = PtrToStringChars(tamUri);
    return TamBrokerProcess(tamUriW);
#else
    return 0;
#endif
}

void ManagedType::TamBrokerStop()
{
    //StopTamBroker();
}

teep_error_code_t TamQueueOutboundTeepMessage(void* sessionHandle, const char* mediaType, const char* message, size_t messageLength)
{
    TeepBasicSession* session = (TeepBasicSession*)sessionHandle;

    assert(session->OutboundMessage == nullptr);

    // Save message for later transmission.
    char* data = (char*)malloc(messageLength);
    if (data == nullptr) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    memcpy(data, message, messageLength);
    session->OutboundMessage = data;
    session->OutboundMessageLength = messageLength;
    printf("Sending %zd bytes...\n", messageLength);

    strcpy_s(session->OutboundMediaType, sizeof(session->OutboundMediaType), mediaType);
    return TEEP_ERR_SUCCESS;
}