// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "catch.hpp"
#include "TeepAgentLib.h"
#define TRUE 1

TEST_CASE("Start-Stop Agent Broker", "[agent]") {
    REQUIRE(StartAgentBroker(TRUE) == 0);
    StopAgentBroker();
}