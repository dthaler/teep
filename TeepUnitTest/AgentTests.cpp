// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "catch.hpp"
#include "TeepAgentBrokerLib.h"
#define TRUE 1

#define TEEP_AGENT_DATA_DIRECTORY "../../../agent"

TEST_CASE("Start-Stop Agent Broker", "[agent]") {
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE) == 0);
    StopAgentBroker();
}