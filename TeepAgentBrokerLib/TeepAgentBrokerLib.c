/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <windows.h> // for Sleep()
#include <openenclave/host.h>
#include "TeepAgentBrokerLib.h"
#include "TeepAgent_u.h"
#include "TeepSession.h"
#ifdef USE_TCP
#include "TcpClient.h"
#else
#include "HttpClient.h"
#endif

#define ASSERT(x) if (!(x)) { DebugBreak(); }

oe_enclave_t* g_ta_eid = NULL;

static int HandleMessages(void)
{
    // Handle messages until we have no outstanding HTTP responses.
    while (g_Session.InboundMessage != NULL || g_Session.OutboundMessage != NULL) {
        if (g_Session.OutboundMessage != NULL) {
            // Send outbound message and get the response.
            char* inboundMediaType;
            int inboundMessageLength;
            const char* inboundMessage = SendTeepMessage(&g_Session, &inboundMediaType, &inboundMessageLength);
            if (inboundMessage != NULL) {
                if (inboundMessage[0] == 0) {
                    // Empty buffer, meaning the TAM is done.
                    free((void*)inboundMessage);
                } else {
                    ASSERT(g_Session.InboundMessage == NULL);
                    g_Session.InboundMessage = inboundMessage;
                    g_Session.InboundMessageLength = inboundMessageLength;
                    strcpy_s(g_Session.InboundMediaType, sizeof(g_Session.InboundMediaType), inboundMediaType);
                }
                free((void*)inboundMediaType);
            }
        }

        if (g_Session.InboundMessage != NULL) {
            int err;
            oe_result_t result = ecall_ProcessTeepMessage(
                g_ta_eid,
                &err,
                &g_Session,
                g_Session.InboundMediaType,
                g_Session.InboundMessage,
                g_Session.InboundMessageLength);

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

int AgentBrokerRequestTA(
    int useCbor,
    oe_uuid_t requestedTaid,
    _In_z_ const char* tamUri)
{
    int err;

    // Invoke a "RequestTA" API in the agent.
    oe_result_t result = ecall_RequestTA(g_ta_eid, &err, useCbor, requestedTaid, tamUri);
    if (result != OE_OK) {
        return result;
    }
    if (err != 0) {
        return err;
    }

    return HandleMessages();
}

int AgentBrokerUnrequestTA(
    int useCbor,
    oe_uuid_t unneededTaid,
    _In_z_ const char* tamUri)
{
    int err;

    // Invoke an "UnrequestTA" API in the agent.
    oe_result_t result = ecall_UnrequestTA(g_ta_eid, &err, useCbor, unneededTaid, tamUri);
    if (result != OE_OK) {
        return result;
    }
    if (err != 0) {
        return err;
    }

    return HandleMessages();
}
