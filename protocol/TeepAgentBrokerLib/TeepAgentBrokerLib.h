// Copyright (c) TEEP contributors
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

int StartAgentBroker(_In_z_ const char* data_directory, int simulated_tee, _Out_writes_opt_z_(256) char* public_key_filename);
void StopAgentBroker(void);

#ifdef __cplusplus
};
#endif

// Other prototypes are the same as in the TEE.
#include "..\TeepAgentLib\TeepAgentLib.h"
