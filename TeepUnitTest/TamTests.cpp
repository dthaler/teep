// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include "catch.hpp"
#include "TeepTamBrokerLib.h"
#define TRUE 1
#define TAM_DATA_DIRECTORY "../../../tam"

TEST_CASE("Start-Stop TAM Broker", "[tam]") {
    REQUIRE(StartTamBroker(TAM_DATA_DIRECTORY, TRUE, nullptr) == 0);
    StopTamBroker();
}