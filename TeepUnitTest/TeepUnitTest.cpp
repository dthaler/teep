// TeepUnitTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "TeepAgentLib.h"

TEST_CASE("Start-Stop Agent Broker", "[agent]") {
    REQUIRE(StartAgentBroker(TRUE) == 0);
    StopAgentBroker();
}