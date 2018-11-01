/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#include "TcpServer.h"
#include "..\TamLib\SgxHost.h"

#define ENCLAVE_FILENAME "OTrPTamTA.signed.dll"
#define TOKEN_FILENAME   "OTrPTamTA.token"

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
        
    err = StartTcpServer();
    if (err != 0) {
        printf("Error %d starting transport\n", err);
        return err;
    }

    AcceptTcpSession();

    while (HandleTcpMessage() == 0);

    StopTcpServer();
    return 0;
}

