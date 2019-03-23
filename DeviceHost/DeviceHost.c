/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#include "../OTrPAgentBrokerLib/OTrPAgentBrokerLib.h"

//#define DEFAULT_TAM_URI "http://127.0.0.1:12345/OTrP"
#define DEFAULT_TAM_URI "http://localhost:54321/OTrP"

int main(int argc, char** argv)
{
    const char* taNeeded;
    if (argc > 1) {
        taNeeded = argv[1];
    } else {
        taNeeded = "X";
    }

    int err = StartAgentBroker();
    if (err != 0) {
        return err;
    }

    err = AgentBrokerRequestTA(taNeeded, DEFAULT_TAM_URI);
    if (err != 0) {
        goto exit;
    }

exit:
    StopAgentBroker();

    printf("Press Enter to exit\n");
    int c = getchar();
    return err;
}
