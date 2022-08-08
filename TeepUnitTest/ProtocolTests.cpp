// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "catch.hpp"
#include "MockHttpTransport.h"
#include "TeepAgentBrokerLib.h"
#include "TeepAgentLib.h"
#include "TeepTamBrokerLib.h"
#include "TeepTamLib.h"
#define TRUE 1
#define TAM_DATA_DIRECTORY "./tam"
#define TEEP_AGENT_DATA_DIRECTORY "./agent"
#define DEFAULT_TA_ID "38b08738-227d-4f6a-b1f0-b208bc02a781"
#define DEFAULT_TAM_URI "http://example.com/tam"

// Returns 0 on success, error on failure.
static int ConvertStringToUUID(_Out_ teep_uuid_t* uuid, _In_z_ const char* idString)
{
    const char* p = idString;
    int length = 0;
    int value;
    while (length < TEEP_UUID_SIZE) {
        if (*p == '-') {
            p++;
            continue;
        }
        if (sscanf_s(p, "%02x", &value) == 0) {
            return 1;
        }
        uuid->b[length++] = value;
        p += 2;
    }
    if (*p != 0) {
        return 1;
    }
    return 0;
}

TEST_CASE("UnrequestTA", "[protocol]")
{
    REQUIRE(StartTamBroker(TAM_DATA_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);

    teep_uuid_t unneededTaid;
    int err = ConvertStringToUUID(&unneededTaid, DEFAULT_TA_ID);
    REQUIRE(err == 0);
    teep_error_code_t teep_error = TeepAgentUnrequestTA(unneededTaid, DEFAULT_TAM_URI);
    REQUIRE(teep_error == TEEP_ERR_SUCCESS);

    StopAgentBroker();
    StopTamBroker();
}

TEST_CASE("RequestTA", "[protocol]")
{
    REQUIRE(StartTamBroker(TAM_DATA_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);

    teep_uuid_t requestedTaid;
    int err = ConvertStringToUUID(&requestedTaid, DEFAULT_TA_ID);
    REQUIRE(err == 0);
    teep_error_code_t teep_error = TeepAgentRequestTA(requestedTaid, DEFAULT_TAM_URI);
    REQUIRE(teep_error == TEEP_ERR_SUCCESS);

    StopAgentBroker();
    StopTamBroker();
}

TEST_CASE("PolicyCheck with no policy change", "[protocol]")
{
    REQUIRE(StartTamBroker(TAM_DATA_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);

    teep_error_code_t teep_error = TeepAgentRequestPolicyCheck(DEFAULT_TAM_URI);
    REQUIRE(teep_error == TEEP_ERR_SUCCESS);

    StopAgentBroker();
    StopTamBroker();
}

// TODO: implement a test for a PolicyCheck when there is a policy change.

TEST_CASE("Unexpected ProcessError", "[protocol]")
{
    REQUIRE(StartTamBroker(TAM_DATA_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);

    teep_error_code_t teep_error = TeepAgentProcessError(nullptr);
    REQUIRE(teep_error == TEEP_ERR_TEMPORARY_ERROR);

    StopAgentBroker();
    StopTamBroker();
}

TEST_CASE("RequestPolicyCheck errors", "[protocol]")
{
    REQUIRE(StartTamBroker(TAM_DATA_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);

    // Schedule a transport error during each of the 3 operations:
    // Connect, QueryRequest, QueryResponse.
    for (int count = 1; count <= 3; count++) {
        ScheduleTransportError(count);

        teep_error_code_t teep_error = TeepAgentRequestPolicyCheck(DEFAULT_TAM_URI);
        REQUIRE(teep_error == TEEP_ERR_TEMPORARY_ERROR);
    }

    StopAgentBroker();
    StopTamBroker();
}

TEST_CASE("Agent receives bad media type", "[protocol]")
{
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);

    // Try bad media type.
    void* sessionHandle = nullptr;
    std::string message = "hello";
    teep_error_code_t teep_error = TeepAgentProcessTeepMessage(
        sessionHandle, "mediaType", message.c_str(), message.size());
    REQUIRE(teep_error == TEEP_ERR_PERMANENT_ERROR);

    // Silent drop.
    // TODO: verify no message sent.

    StopAgentBroker();
}

TEST_CASE("Agent receives bad COSE message", "[protocol]")
{
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);

    // Try bad COSE message.
    void* sessionHandle = nullptr;
    std::string message = "hello";
    teep_error_code_t teep_error = TeepAgentProcessTeepMessage(
        sessionHandle, TEEP_CBOR_MEDIA_TYPE, message.c_str(), message.size());
    REQUIRE(teep_error == TEEP_ERR_PERMANENT_ERROR);

    // Silent drop.
    // TODO: verify no message sent.

    StopAgentBroker();
}

#include "..\external\qcbor\inc\UsefulBuf.h"

teep_error_code_t
TamSignCborMessage(
    _In_ const UsefulBufC* unsignedMessage,
    _In_ UsefulBuf signedMessageBuffer,
    _Out_ UsefulBufC* signedMessage);

TEST_CASE("Agent receives bad TEEP message", "[protocol]")
{
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);

    // Compose a bad TEEP message.
    std::string message = "hello";
    UsefulBufC unsignedMessage;
    unsignedMessage.ptr = message.c_str();
    unsignedMessage.len = message.size();
    UsefulBufC signedMessage;
    UsefulBuf_MAKE_STACK_UB(signedMessageBuffer, 300);
    teep_error_code_t teep_error = TamSignCborMessage(&unsignedMessage, signedMessageBuffer, &signedMessage);
    REQUIRE(teep_error == TEEP_ERR_SUCCESS);

    // Try bad COSE message.
    void* sessionHandle = nullptr;
    teep_error = TeepAgentProcessTeepMessage(
        sessionHandle, TEEP_CBOR_MEDIA_TYPE, (const char*)signedMessage.ptr, signedMessage.len);
    REQUIRE(teep_error == TEEP_ERR_PERMANENT_ERROR);

    // Silent drop.
    // TODO: verify no message sent.

    StopAgentBroker();
}