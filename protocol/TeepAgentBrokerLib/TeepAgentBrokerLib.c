// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include <direct.h>
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
    while (g_Session.InboundMessage != NULL || g_Session.Basic.OutboundMessage != NULL) {
        if (g_Session.Basic.OutboundMessage != NULL) {
            // Send outbound message and get the response.
            char* inboundMediaType;
            int inboundMessageLength;
            const char* inboundMessage = TeepAgentSendMessage(&g_Session, &inboundMediaType, &inboundMessageLength);
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
            int err = TeepAgentProcessTeepMessage(
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
    teep_uuid_t requestedTaid,
    _In_z_ const char* tamUri)
{
    int err;

    // Invoke a "RequestTA" API in the agent.
    err = TeepAgentRequestTA(requestedTaid, tamUri);
    if (err != 0) {
        return err;
    }

    return HandleMessages();
}

int AgentBrokerUnrequestTA(
    teep_uuid_t unneededTaid,
    _In_z_ const char* tamUri)
{
    int err;

    // Invoke an "UnrequestTA" API in the agent.
    err = TeepAgentUnrequestTA(unneededTaid, tamUri);
    if (err != 0) {
        return err;
    }

    return HandleMessages();
}

int StartAgentBroker(_In_z_ const char* dataDirectory, int simulatedTee, teep_signature_kind_t signatureKind, _Out_writes_opt_z_(256) char* publicKeyFilename)
{
    // Create data directory if it doesn't already exist.
    _mkdir(dataDirectory);

    // Make "trusted" directory if it doesn't already exist.
    char directory[256];
    sprintf_s(directory, sizeof(directory), "%s/trusted", dataDirectory);
    _mkdir(directory);

    // Make "untrusted" directory if it doesn't already exist.
    sprintf_s(directory, sizeof(directory), "%s/untrusted", dataDirectory);
    _mkdir(directory);

#ifdef TEEP_USE_TEE
    int result = StartAgentTABroker(simulatedTee);
    return result;
#else
    teep_error_code_t result = TeepAgentLoadConfiguration(dataDirectory);
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }

    return TeepAgentInitializeKeys(dataDirectory, signatureKind, publicKeyFilename);
#endif
}

void StopAgentBroker(void)
{
#ifdef TEEP_USE_TEE
    StopAgentTABroker();
#endif
}
