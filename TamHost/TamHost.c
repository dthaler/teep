// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>
#include "../protocol/TeepTamBrokerLib/TeepTamBrokerLib.h"
#if 0
#pragma warning(push)
#pragma warning(disable:4996)
#include "openssl/applink.c"
#pragma warning(pop)
#endif

#define DEFAULT_MANIFEST_DIRECTORY "../../../manifests"

int wmain(int argc, wchar_t** argv)
{
    int simulated_tee = 0;
    if ((argc > 1) && (wcscmp(argv[1], L"-s") == 0)) {
        simulated_tee = 1;
        argc--;
        argv++;
    }

    if (argc < 2) {
        printf("Usage: TamHost [-s] <TAM URI>\n");
        printf("       where -s if present means to only simulate a TEE\n");
        printf("             <TAM URI> is the TAM URI to use, e.g., http://192.168.1.37:54321/TEEP\n");
        printf("\nCurrently the <TAM URI> must end in /TEEP\n");
        return 0;
    }

    const wchar_t* tamUri = argv[1];
    printf("Listening on TAM URI: %ls\n", tamUri);

    int err = StartTamBroker(DEFAULT_MANIFEST_DIRECTORY, simulated_tee);
    if (err != 0) {
        return err;
    }

    err = TamBrokerProcess(tamUri);

    StopTamBroker();

    printf("Press Enter to exit\n");
    int c = getchar();
    return err;
}
