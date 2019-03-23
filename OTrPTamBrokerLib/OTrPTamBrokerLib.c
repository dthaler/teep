/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <string.h>
#include "OTrPTamBrokerLib.h"
#include "OTrPTam_u.h"
#ifdef USE_TCP
#include "TcpServer.h"
#else
#include "HttpServer.h"
#endif

oe_enclave_t* g_ta_eid = NULL;

// Forward an incoming OTrP message, which might be from any session.
int OTrPHandleMessage(
    void* sessionHandle,
    const char *message,
    int messageLength)
{
    int err = 0;
    oe_result_t result = ecall_ProcessOTrPMessage(g_ta_eid, &err, sessionHandle, message, messageLength);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

int OTrPHandleConnect(void* sessionHandle)
{
    int err = 0;
    oe_result_t result = ecall_ProcessOTrPConnect(g_ta_eid, &err, sessionHandle);
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