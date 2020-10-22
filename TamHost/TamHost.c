/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#include "../TeepTamBrokerLib/TeepTamBrokerLib.h"

#define DEFAULT_MANIFEST_DIRECTORY "../../../manifests"

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) {
        printf("Usage: TamHost <TAM URI>\n");
        printf("       where <TAM URI> is the TAM URI to use, e.g., http://192.168.1.37:54321/TEEP\n");
        printf("\nCurrently the <TAM URI> must end in /TEEP\n");
        return 0;
    }

    const wchar_t* tamUri = argv[1];
    printf("Using TAM URI: %ls\n", tamUri);

    int err = StartTamBroker(DEFAULT_MANIFEST_DIRECTORY);
    if (err != 0) {
        return err;
    }

    err = TamBrokerProcess(tamUri);

    StopTamBroker();

    printf("Press Enter to exit\n");
    int c = getchar();
    return err;
}