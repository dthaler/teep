// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include "common.h"

int AgentBrokerRequestTA(
    teep_uuid_t unneededTaid,
    _In_z_ const char* tamUri);

int AgentBrokerUnrequestTA(
    teep_uuid_t unneededTaid,
    _In_z_ const char* tamUri);

#ifdef __cplusplus
extern "C" {
#endif

int StartAgentBroker(int simulated_tee);
void StopAgentBroker(void);

#ifdef __cplusplus
};
#endif

// Other prototypes are the same as in the TEE.
#include "..\TeepAgentLib\TeepAgentLib.h"