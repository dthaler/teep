/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#include <string.h>
#include <openenclave/host.h>
#include "../TeepAgentBrokerLib/TeepAgentBrokerLib.h"

//#define DEFAULT_TAM_URI "http://127.0.0.1:12345/TEEP"
//#define DEFAULT_TAM_URI "http://localhost:54321/TEEP"
//#define DEFAULT_TAM_URI "http://192.168.11.23:54321/TEEP"
//#define DEFAULT_TAM_URI "http://192.168.11.10:8888/api/tam"

#define DEFAULT_TA_ID "38b08738-227d-4f6a-b1f0-b208bc02a781" // TODO: default to none

// Returns 0 on success, error on failure.
int ConvertStringToUUID(oe_uuid_t* uuid, const char* idString)
{
    const char* p = idString;
    int length = 0;
    int value;
    while (length < OE_UUID_SIZE) {
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
    if (argc < 2) {
        printf("Usage: DeviceHost [-j] [-s] <TAM URI> [<TA ID>]\n");
        printf("       where -j if present means to try JSON instead of CBOR\n");
        printf("             -s if present means to only simulate a TEE\n");
        printf("             <TAM URI> is the default TAM URI to use\n");
        printf("             <TA ID> is the TA ID to request (%s if none specified)\n", DEFAULT_TA_ID);
        return 0;
    }

    int useCbor = 1;
    int simulated_tee = 0;
    if ((argc > 2) && (strcmp(argv[1], "-j") == 0)) {
        useCbor = 0;
        argc--;
        argv++;
    }
    if ((argc > 2) && (strcmp(argv[1], "-s") == 0)) {
        simulated_tee = 1;
        argc--;
        argv++;
    }

    const char* defaultTamUri = argv[1];
    printf("Using default TAM URI: %s\n", defaultTamUri);

    const char* requestedTa = DEFAULT_TA_ID;
    if (argc > 2) {
        requestedTa = argv[2];
    }
    
    oe_uuid_t requestedTaid;
    int err = ConvertStringToUUID(&requestedTaid, requestedTa);
    if (err != 0) {
        printf("Invalid TA ID: %s\n", requestedTa);
        return err;
    }
    printf("Using TA ID: %s\n", requestedTa);

    err = StartAgentBroker(simulated_tee);
    if (err != 0) {
        return err;
    }

    err = AgentBrokerRequestTA(useCbor, requestedTaid, defaultTamUri);
    if (err != 0) {
        goto exit;
    }

exit:
    StopAgentBroker();

    printf("Press Enter to exit\n");
    int c = getchar();
    return err;
}
