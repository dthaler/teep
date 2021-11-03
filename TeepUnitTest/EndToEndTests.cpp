// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "catch.hpp"
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

TEST_CASE("UnrequestTA", "[end-to-end]") {
    REQUIRE(StartTamBroker(DEFAULT_MANIFEST_DIRECTORY, TRUE) == 0);
    REQUIRE(StartAgentBroker(TRUE) == 0);

    const int useCbor = 1;
    teep_uuid_t unneededTaid;
    int err = ConvertStringToUUID(&unneededTaid, DEFAULT_TA_ID);
    REQUIRE(err == 0);
    err = UnrequestTA(useCbor, unneededTaid, DEFAULT_TAM_URI);
    REQUIRE(err == 0);

    StopAgentBroker();
    StopTamBroker();
}