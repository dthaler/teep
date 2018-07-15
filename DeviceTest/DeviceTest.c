/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#include <Windows.h>
#include "TcpClient.h"
#include "..\DeviceLib\SgxHost.h"

#define ENCLAVE_FILENAME "OTrPDeviceTA.signed.dll"
#define TOKEN_FILENAME   "OTrPDeviceTA.token"

int main(int argc, char** argv)
{
    int err;

    if (query_sgx_status() < 0) {
        printf("either SGX is disabled, or a reboot is required to enable SGX\n");
        return 1;
    }

    /* Initialize the enclave */
    if (initialize_enclave(TOKEN_FILENAME, ENCLAVE_FILENAME) < 0) {
        return 1;
    }

    /* Connect to the TAM. */
    for (;;) {
        err = ConnectToTcpServer("localhost");
        if (err != 0) {
            printf("Waiting for server to become available...\n");
            Sleep(1000);
            continue;
        }

        /* We are now connected. */
        break;
    }
     
    /* Currently OTrP has the TAM generate the first message. This seems inefficient. */
    while (HandleTcpMessage());

    /* Clean up. */
    DisconnectFromTcpServer();
    return 0;
}
