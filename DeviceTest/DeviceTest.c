/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#ifdef USE_TCP
#include "TcpClient.h"
#else
#include "HttpClient.h"
#endif
#include "../OTrPAgentBrokerLib/OTrPAgentBrokerLib.h"
#include "Windows.h" // for Sleep()

//#define DEFAULT_TAM_URI "http://127.0.0.1:12345/"
#define DEFAULT_TAM_URI "localhost:54321"

int main(int argc, char** argv)
{
    int err;

    err = StartAgentBroker();
    if (err != 0) {
        return err;
    }

    /* Connect to the TAM. */
    const char* response = NULL;
    for (;;) {
#ifdef USE_TCP
        err = ConnectToTcpServer("localhost");
        if (err != 0)
#else
        response = ConnectToTam(DEFAULT_TAM_URI);
        if (response == NULL)
#endif
        {
            printf("Waiting for server to become available...\n");
            Sleep(1000);
            continue;
        }

        /* We are now connected. */
        break;
    }

#ifdef USE_TCP
    while (HandleTcpMessage());
#else
    do {
        response = HandleHttpResponse(response, DEFAULT_TAM_URI);
    } while (response != NULL);
#endif

#ifdef USE_TCP
    /* Clean up. */
    DisconnectFromTcpServer();
#endif

    StopAgentBroker();
    return 0;
}
