/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#include "../TeepAgentBrokerLib/TeepAgentBrokerLib.h"

//#define DEFAULT_TAM_URI "http://127.0.0.1:12345/TEEP"
//#define DEFAULT_TAM_URI "http://localhost:54321/TEEP"
//#define DEFAULT_TAM_URI "http://192.168.11.23:54321/TEEP"
//#define DEFAULT_TAM_URI "http://192.168.11.10:8888/api/tam"

#define DEFAULT_TA_ID "X" // TODO: default to none

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("Usage: DeviceHost <TAM URI> [<TA ID>]\n");
        printf("       where <TAM URI> is the default TAM URI to use\n");
        printf("             <TA ID> is the TA to request (%s if none specified)\n", DEFAULT_TA_ID);
        return 0;
    }

    const char* defaultTamUri = argv[1];
    printf("Using default TAM URI: %s\n", defaultTamUri);

    const char* taNeeded = DEFAULT_TA_ID;
    if (argc > 2) {
        taNeeded = argv[2];
    }
    printf("Using TA ID: %s\n", taNeeded);

    int err = StartAgentBroker();
    if (err != 0) {
        return err;
    }

    err = AgentBrokerRequestTA(taNeeded, defaultTamUri);
    if (err != 0) {
        goto exit;
    }

exit:
    StopAgentBroker();

    printf("Press Enter to exit\n");
    int c = getchar();
    return err;
}
