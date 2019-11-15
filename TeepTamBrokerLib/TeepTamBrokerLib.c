/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <string.h>
#include "TeepTamBrokerLib.h"
#include "TeepTam_u.h"
#ifdef USE_TCP
#include "TcpServer.h"
#else
#include "HttpServer.h"
#endif

oe_enclave_t* g_ta_eid = NULL;

// Forward an incoming TEEP message, which might be from any session.
int TeepHandleMessage(
    void* sessionHandle,
    const char *message,
    int messageLength)
{
    int err = 0;
    oe_result_t result = ecall_ProcessTeepMessage(g_ta_eid, &err, sessionHandle, message, messageLength);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

int TeepHandleConnect(void* sessionHandle)
{
    int err = 0;
    oe_result_t result = ecall_ProcessTeepConnect(g_ta_eid, &err, sessionHandle);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

int TamBrokerProcess(void)
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
    wchar_t* myargv[2] = { NULL, OTRP_URI };
    err = RunHttpServer(2, myargv);
#endif

    return err;
}
