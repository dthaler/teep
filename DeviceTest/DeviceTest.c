/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#include <Windows.h>
#ifdef USE_TCP
#include "TcpClient.h"
#else
#include "HttpClient.h"
#endif
#include "..\DeviceLib\SgxHost.h"

#define ENCLAVE_FILENAME "OTrPDeviceTA.signed.dll"
#define TOKEN_FILENAME   "OTrPDeviceTA.token"

//#define DEFAULT_TAM_URI "http://127.0.0.1:12345/"
//#define DEFAULT_TAM_URI "127.0.0.1:12345"
#define DEFAULT_TAM_URI "ietf.org"

#define DEFAULT_TA_ID "abcdef"

int main(int argc, char** argv)
{
#ifdef USE_TCP
    int err;
#endif

    if (query_sgx_status() < 0) {
        printf("either SGX is disabled, or a reboot is required to enable SGX\n");
        return 1;
    }

    /* Initialize the enclave */
    if (initialize_enclave(TOKEN_FILENAME, ENCLAVE_FILENAME) < 0) {
        return 1;
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
    return 0;
}
