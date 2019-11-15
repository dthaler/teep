/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#include "../TeepTamBrokerLib/TeepTamBrokerLib.h"

int main(int argc, char** argv)
{
    int err;

    err = StartTamBroker();
    if (err != 0) {
        return err;
    }

    err = TamBrokerProcess();

    StopTamBroker();

    printf("Press Enter to exit\n");
    int c = getchar();
    return err;
}