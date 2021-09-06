// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <windows.h> // for Sleep()
#include "TeepAgentBrokerLib.h"
#include "TeepSession.h"
#ifdef USE_TCP
#include "TcpClient.h"
#else
#include "HttpClient.h"
#endif

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
                    TEEP_ASSERT(g_Session.InboundMessage == NULL);
                    g_Session.InboundMessage = inboundMessage;
                    g_Session.InboundMessageLength = inboundMessageLength;
                    strcpy_s(g_Session.InboundMediaType, sizeof(g_Session.InboundMediaType), inboundMediaType);
                }
                free((void*)inboundMediaType);
            }
        }

        if (g_Session.InboundMessage != NULL) {
            int err = ProcessTeepMessage(
                &g_Session,
                g_Session.InboundMediaType,
                g_Session.InboundMessage,
                g_Session.InboundMessageLength);

            free((void*)g_Session.InboundMessage);
            g_Session.InboundMessage = NULL;

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
    teep_uuid_t requestedTaid,
    _In_z_ const char* tamUri)
{
    int err;

    // Invoke a "RequestTA" API in the agent.
    err = RequestTA(useCbor, requestedTaid, tamUri);
    if (err != 0) {
        return err;
    }

    return HandleMessages();
}

int AgentBrokerUnrequestTA(
    int useCbor,
    teep_uuid_t unneededTaid,
    _In_z_ const char* tamUri)
{
    int err;

    // Invoke an "UnrequestTA" API in the agent.
    err = UnrequestTA(useCbor, unneededTaid, tamUri);
    if (err != 0) {
        return err;
    }

    return HandleMessages();
}

int StartAgentBroker(int simulated_tee)
{
#ifdef TEEP_USE_TEE
    int result = StartAgentTABroker(simulated_tee);
    if (result)
        return result;
#endif

    return TeepInitialize();
}

void StopAgentBroker(void)
{
#ifdef TEEP_USE_TEE
    StopAgentTABroker();
#endif
}