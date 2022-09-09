// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <direct.h>
#include <string.h>
#include "TeepTamBrokerLib.h"
#ifdef USE_TCP
#include "TcpServer.h"
#else
#include "HttpServer.h"
#endif

int TamBrokerProcess(_In_z_ const wchar_t* tamUri)
{
    int err;

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
    const wchar_t* myargv[2] = { NULL, tamUri };
    err = RunHttpServer(2, myargv);
#endif

    return err;
}

int StartTamBroker(_In_z_ const char* data_directory, int simulated_tee)
{
    // Create data directory if it doesn't already exist.
    _mkdir(data_directory);

#ifdef TEEP_USE_TEE
    int result = StartTamTABroker(data_directory, simulated_tee);
    if (result)
        return result;
#endif

    return TeepInitialize();
}

void StopTamBroker(void)
{
#ifdef TEEP_USE_TEE
    StopTamTABroker();
#endif
}