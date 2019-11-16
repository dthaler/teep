/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include "TeepAgentBrokerLib.h"
#include "TeepAgent_u.h"
#include "TeepSession.h"
#ifdef USE_TCP
#include "TcpClient.h"
#else
#include "HttpClient.h"
#endif
#include <windows.h> // for Sleep()

#define ASSERT(x) if (!(x)) { DebugBreak(); }

oe_enclave_t* g_ta_eid = NULL;

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
    while (g_Session.InboundMessage != NULL || g_Session.OutboundMessage != NULL) {
        if (g_Session.OutboundMessage != NULL) {
            // Send outbound message and get the response.
            const char* inboundMessage = SendTeepMessage(&g_Session);
            if (inboundMessage != NULL) {
                if (inboundMessage[0] == 0) {
                    // Empty buffer, meaning the TAM is done.
                    free((void*)inboundMessage);
                } else {
                    ASSERT(g_Session.InboundMessage == NULL);
                    g_Session.InboundMessage = inboundMessage;
                }
            }
        }

        if (g_Session.InboundMessage != NULL) {
            result = ecall_ProcessTeepMessage(
                g_ta_eid,
                &err,
                &g_Session,
                g_Session.InboundMediaType,
                g_Session.InboundMessage,
                strlen(g_Session.InboundMessage));

            free((void*)g_Session.InboundMessage);
            g_Session.InboundMessage = NULL;

            if (result != OE_OK) {
                return result;
            }
            if (err != 0) {
                return err;
            }
        }
    }

    printf("Done with request\n");
    return 0;
}
