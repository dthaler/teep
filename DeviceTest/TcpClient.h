/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

int ConnectToTcpServer(const char* serverName);
int HandleTcpMessage(void);
void DisconnectFromTcpServer(void);
