// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include <direct.h>
#include <stdio.h>
#include <string.h>
#include "TeepTamBrokerLib.h"
#ifdef USE_TCP
#include "TcpServer.h"
#else
#include "HttpServer.h"
#endif
#ifndef TEEP_USE_TEE
#include "TeepTamLib.h"
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

int StartTamBroker(_In_z_ const char* dataDirectory, int simulatedTee)
{
    // Create data directory if it doesn't already exist.
    _mkdir(dataDirectory);

    // Make "trusted" directory if it doesn't already exist.
    char directory[256];
    sprintf_s(directory, sizeof(directory), "%s/trusted", dataDirectory);
    _mkdir(directory);

    // Make "untrusted" directory if it doesn't already exist.
    sprintf_s(directory, sizeof(directory), "%s/untrusted", dataDirectory);
    _mkdir(directory);

#ifdef TEEP_USE_TEE
    int result = StartTamTABroker(dataDirectory, simulatedTee);
    return result;
#else
    teep_error_code_t result = TamLoadConfiguration(dataDirectory);
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }

    return TamInitializeKeys(dataDirectory);
#endif
}

void StopTamBroker(void)
{
#ifdef TEEP_USE_TEE
    StopTamTABroker();
#endif
}