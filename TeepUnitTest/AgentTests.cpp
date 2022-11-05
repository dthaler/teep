// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include "catch.hpp"
#include "TeepAgentBrokerLib.h"
#define TRUE 1

#define TEEP_AGENT_DATA_DIRECTORY "../../../agent"

TEST_CASE("Start-Stop Agent Broker", "[agent]") {
    REQUIRE(StartAgentBroker(TEEP_AGENT_DATA_DIRECTORY, TRUE, TEEP_SIGNATURE_ES256, nullptr) == 0);
    StopAgentBroker();
}