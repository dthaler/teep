// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include "common.h"

int AgentBrokerRequestTA(
    int useCbor,
    teep_uuid_t unneededTaid,
    _In_z_ const char* tamUri);

int AgentBrokerUnrequestTA(
    int useCbor,
    teep_uuid_t unneededTaid,
    _In_z_ const char* tamUri);

// Other prototypes are the same as in the TEE.
#include "..\TeepAgentLib\TeepAgentLib.h"