/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#ifdef USE_TCP
#include "TcpServer.h"
#else
#include "HttpServer.h"
#endif
#include "../OTrPTamBrokerLib/OTrPTamBrokerLib.h"

int main(int argc, char** argv)
{
    int err;

    err = StartTamBroker();
    if (err != 0) {
        return err;
    }

#ifdef USE_TCP
    err = StartTcpServer();
    if (err != 0) {
        printf("Error %d starting transport\n", err);
        return err;
    }

    for (;;) {
        printf("Waiting for client...\n");

        AcceptTcpSession();

        printf("Accepted client connection...\n");

        while (HandleTcpMessage() == 0);

        CloseTcpSession();
    }

    StopTcpServer();
#else
    wchar_t* myargv[2] = { NULL, OTRP_URI };
    err = RunHttpServer(2, myargv);
#endif

    StopTamBroker();
    return 0;
}