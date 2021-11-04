// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "catch.hpp"
#include "MockHttpTransport.h"
#include "TeepAgentLib.h"
#include "TeepTamLib.h"
#define TRUE 1
#define DEFAULT_MANIFEST_DIRECTORY "../../../manifests"
#define DEFAULT_TA_ID "38b08738-227d-4f6a-b1f0-b208bc02a781"
#define DEFAULT_TAM_URI "http://example.com/tam"

// Returns 0 on success, error on failure.
int ConvertStringToUUID(teep_uuid_t* uuid, const char* idString)
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
    REQUIRE(StartTamBroker(DEFAULT_MANIFEST_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TRUE) == 0);

    const int useCbor = 1;
    teep_uuid_t unneededTaid;
    int err = ConvertStringToUUID(&unneededTaid, DEFAULT_TA_ID);
    REQUIRE(err == 0);
    err = TeepAgentUnrequestTA(useCbor, unneededTaid, DEFAULT_TAM_URI);
    REQUIRE(err == 0);

    StopAgentBroker();
    StopTamBroker();
}

TEST_CASE("RequestTA", "[protocol]")
{
    REQUIRE(StartTamBroker(DEFAULT_MANIFEST_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TRUE) == 0);

    const int useCbor = 1;
    teep_uuid_t requestedTaid;
    int err = ConvertStringToUUID(&requestedTaid, DEFAULT_TA_ID);
    REQUIRE(err == 0);
    err = TeepAgentRequestTA(useCbor, requestedTaid, DEFAULT_TAM_URI);
    REQUIRE(err == 0);

    StopAgentBroker();
    StopTamBroker();
}

TEST_CASE("PolicyCheck with no policy change", "[protocol]")
{
    REQUIRE(StartTamBroker(DEFAULT_MANIFEST_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TRUE) == 0);

    int err = TeepAgentRequestPolicyCheck(DEFAULT_TAM_URI);
    REQUIRE(err == 0);

    StopAgentBroker();
    StopTamBroker();
}

// TODO: implement a test for a PolicyCheck when there is a policy change.

TEST_CASE("Unexpected ProcessError", "[protocol]")
{
    REQUIRE(StartTamBroker(DEFAULT_MANIFEST_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TRUE) == 0);

    teep_error_code_t err = TeepAgentProcessError(nullptr);
    REQUIRE(err == TEEP_ERR_TEMPORARY_ERROR);

    StopAgentBroker();
    StopTamBroker();
}

TEST_CASE("RequestPolicyCheck errors", "[protocol]")
{
    REQUIRE(StartTamBroker(DEFAULT_MANIFEST_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TRUE) == 0);

    // Schedule a transport error during each of the 3 operations:
    // Connect, QueryRequest, QueryResponse.
    for (int count = 1; count <= 3; count++) {
        ScheduleTransportError(count);

        teep_error_code_t err = TeepAgentRequestPolicyCheck(DEFAULT_TAM_URI);
        REQUIRE(err == TEEP_ERR_TEMPORARY_ERROR);
    }

    StopAgentBroker();
    StopTamBroker();
}