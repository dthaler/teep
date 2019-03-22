/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include "OTrPAgentBrokerLib.h"
#include "OTrPAgent_u.h"
#ifdef USE_TCP
#include "TcpClient.h"
#else
#include "HttpClient.h"
#endif
#include "OTrPSession.h"
#include <windows.h> // for Sleep()

oe_enclave_t* g_ta_eid = NULL;

int OTrPHandleMessage(void* sessionHandle, const char *message, int messageLength)
{
    int err = 0;
    oe_result_t result = ecall_ProcessOTrPMessage(g_ta_eid, &err, sessionHandle, message, messageLength);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

int AgentBrokerRequestTA(
    const char *taid,
    const char *tamUri)
{
    int err;

    // Invoke a "RequestTA" API in the agent.
    oe_result_t result = ecall_RequestTA(g_ta_eid, &err, taid, tamUri);
    if (result != OE_OK) {
        return result;
    }
    if (err != 0) {
        return err;
    }

    // Handle messages until we have no outstanding HTTP responses.
    while (g_Session.ResponseBuffer != NULL) {
        result = ecall_ProcessOTrPMessage(
            g_ta_eid,
            &err,
            &g_Session,
            g_Session.ResponseBuffer,
            strlen(g_Session.ResponseBuffer));
        if (result != OE_OK) {
            return result;
        }
        if (err != 0) {
            return err;
        }
    }

    return 0;
}
