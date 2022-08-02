// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>
#ifdef TEEP_USE_TEE
#include <openenclave/host.h>
#endif
#include "../protocol/TeepAgentBrokerLib/TeepAgentBrokerLib.h"
#pragma warning(push)
#pragma warning(disable:4996)
#include "applink.c"
#pragma warning(pop)

//#define DEFAULT_TAM_URI "http://127.0.0.1:12345/TEEP"
//#define DEFAULT_TAM_URI "http://localhost:54321/TEEP"
//#define DEFAULT_TAM_URI "http://192.168.11.23:54321/TEEP"
//#define DEFAULT_TAM_URI "http://192.168.11.10:8888/api/tam"

#define DEFAULT_TA_ID "38b08738-227d-4f6a-b1f0-b208bc02a781" // TODO: default to none

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

int main(int argc, char** argv)
{
    const char* requestedTa = DEFAULT_TA_ID;
    const char* unneededTa = NULL;
    int simulated_tee = 0;

    if ((argc > 1) && (strcmp(argv[1], "-s") == 0)) {
        simulated_tee = 1;
        argc--;
        argv++;
    }
    if ((argc > 2) && (strcmp(argv[1], "-r") == 0)) {
        requestedTa = argv[2];
        argc -= 2;
        argv += 2;
    }
    if ((argc > 2) && (strcmp(argv[1], "-u") == 0)) {
        unneededTa = argv[2];
        printf("Unneeded TA ID: %s\n", unneededTa);
        argc -= 2;
        argv += 2;
    }

    if (argc < 2) {
        printf("Usage: DeviceHost [-s] [-r <TA ID>] [-u <TA ID>] <TAM URI>\n");
        printf("       where -s if present means to only simulate a TEE\n");
        printf("             -r <TA ID> if present is a TA ID to request (%s if absent)\n", DEFAULT_TA_ID);
        printf("             -u <TA ID> if present is a TA ID that is no longer needed by any normal app\n");
        printf("             <TAM URI> is the default TAM URI to use\n");
        return 0;
    }

    const char* defaultTamUri = argv[1];
    printf("Using default TAM URI: %s\n", defaultTamUri);

    int err = StartAgentBroker(simulated_tee);
    if (err != 0) {
        return err;
    }

    if (unneededTa != NULL) {
        teep_uuid_t unneededTaid;
        err = ConvertStringToUUID(&unneededTaid, unneededTa);
        if (err != 0) {
            printf("Invalid TA ID: %s\n", unneededTa);
            return err;
        }
        err = AgentBrokerUnrequestTA(unneededTaid, defaultTamUri);
        if (err != 0) {
            goto exit;
        }
    }

    if (requestedTa != NULL) {
        teep_uuid_t requestedTaid;
        err = ConvertStringToUUID(&requestedTaid, requestedTa);
        if (err != 0) {
            printf("Invalid TA ID: %s\n", requestedTa);
            return err;
        }
        printf("Requesting TA ID: %s\n", requestedTa);
        err = AgentBrokerRequestTA(requestedTaid, defaultTamUri);
        if (err != 0) {
            goto exit;
        }
    }

exit:
    StopAgentBroker();

    printf("Press Enter to exit\n");
    int c = getchar();
    return err;
}
