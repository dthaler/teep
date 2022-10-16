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

    uint64_t counter1 = GetOutboundMessagesSent();

    teep_uuid_t unneededTaid;
    int err = ConvertStringToUUID(&unneededTaid, DEFAULT_TA_ID);
    REQUIRE(err == 0);
    teep_error_code_t teep_error = TeepAgentUnrequestTA(unneededTaid, DEFAULT_TAM_URI);
    REQUIRE(teep_error == TEEP_ERR_SUCCESS);

    // Verify 2 messages sent (empty connect + QueryResponse).
    uint64_t counter2 = GetOutboundMessagesSent();
    REQUIRE(counter2 == counter1 + 2);

    StopAgentBroker();
    StopTamBroker();
}

TEST_CASE("RequestTA", "[protocol]")
{
    REQUIRE(StartTamBroker(TAM_DATA_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);

    uint64_t counter1 = GetOutboundMessagesSent();

    teep_uuid_t requestedTaid;
    int err = ConvertStringToUUID(&requestedTaid, DEFAULT_TA_ID);
    REQUIRE(err == 0);
    teep_error_code_t teep_error = TeepAgentRequestTA(requestedTaid, DEFAULT_TAM_URI);
    REQUIRE(teep_error == TEEP_ERR_SUCCESS);

    // Verify 2 messages sent (empty connect + QueryResponse).
    uint64_t counter2 = GetOutboundMessagesSent();
    REQUIRE(counter2 == counter1 + 2);

    StopAgentBroker();
    StopTamBroker();
}

TEST_CASE("PolicyCheck with no policy change", "[protocol]")
{
    REQUIRE(StartTamBroker(TAM_DATA_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);

    uint64_t counter1 = GetOutboundMessagesSent();

    teep_error_code_t teep_error = TeepAgentRequestPolicyCheck(DEFAULT_TAM_URI);
    REQUIRE(teep_error == TEEP_ERR_SUCCESS);

    // Verify 2 messages sent (empty connect + QueryResponse).
    uint64_t counter2 = GetOutboundMessagesSent();
    REQUIRE(counter2 == counter1 + 2);

    StopAgentBroker();
    StopTamBroker();
}

// TODO: implement a test for a PolicyCheck when there is a policy change.

TEST_CASE("Unexpected ProcessError", "[protocol]")
{
    REQUIRE(StartTamBroker(TAM_DATA_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);

    uint64_t counter1 = GetOutboundMessagesSent();

    teep_error_code_t teep_error = TeepAgentProcessError(nullptr);
    REQUIRE(teep_error == TEEP_ERR_TEMPORARY_ERROR);

    // Verify no messages sent.
    uint64_t counter2 = GetOutboundMessagesSent();
    REQUIRE(counter2 == counter1);

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
        uint64_t counter1 = GetOutboundMessagesSent();
        ScheduleTransportError(count);

        teep_error_code_t teep_error = TeepAgentRequestPolicyCheck(DEFAULT_TAM_URI);
        REQUIRE(teep_error == TEEP_ERR_TEMPORARY_ERROR);

        // Verify the correct number of messages were sent.
        uint64_t counter2 = GetOutboundMessagesSent();
        REQUIRE(counter2 == counter1 + count - 1);
    }

    StopAgentBroker();
    StopTamBroker();
}

TEST_CASE("Agent receives bad media type", "[protocol]")
{
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);

    uint64_t counter1 = GetOutboundMessagesSent();

    // Try bad media type.
    void* sessionHandle = nullptr;
    std::string message = "hello";
    teep_error_code_t teep_error = TeepAgentProcessTeepMessage(
        sessionHandle, "mediaType", message.c_str(), message.size());
    REQUIRE(teep_error == TEEP_ERR_PERMANENT_ERROR);

    // Silent drop.  Verify no message sent.
    uint64_t counter2 = GetOutboundMessagesSent();
    REQUIRE(counter2 == counter1);

    StopAgentBroker();
}

TEST_CASE("Agent receives bad COSE message", "[protocol]")
{
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);

    uint64_t counter1 = GetOutboundMessagesSent();

    // Try bad COSE message.
    void* sessionHandle = nullptr;
    std::string message = "hello";
    teep_error_code_t teep_error = TeepAgentProcessTeepMessage(
        sessionHandle, TEEP_CBOR_MEDIA_TYPE, message.c_str(), message.size());
    REQUIRE(teep_error == TEEP_ERR_PERMANENT_ERROR);

    // Silent drop.  Verify no message sent.
    uint64_t counter2 = GetOutboundMessagesSent();
    REQUIRE(counter2 == counter1);

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

    uint64_t counter1 = GetOutboundMessagesSent();

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

    // Verify that an Error message was sent.
    uint64_t counter2 = GetOutboundMessagesSent();
    REQUIRE(counter2 == counter1 + 1);

    StopAgentBroker();
}