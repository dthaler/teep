// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

int ConnectToTcpServer(const char* serverName);
int HandleTcpMessage(void);
void DisconnectFromTcpServer(void);
