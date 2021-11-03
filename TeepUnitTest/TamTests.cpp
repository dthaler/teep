// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "catch.hpp"
#include "TeepTamLib.h"
#define TRUE 1
#define DEFAULT_MANIFEST_DIRECTORY "../../../manifests"

TEST_CASE("Start-Stop TAM Broker", "[agent]") {
    REQUIRE(StartTamBroker(DEFAULT_MANIFEST_DIRECTORY, TRUE) == 0);
    StopTamBroker();
}