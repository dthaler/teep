/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#include "TcpServer.h"

int main()
{
    int err = StartTcpServer();
    if (err != 0) {
        printf("Error %d starting transport\n", err);
        return err;
    }

    AcceptTcpSession();

    while (HandleTcpMessage() == 0);

    StopTcpServer();
    return 0;
}

