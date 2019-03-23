/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

int StartTcpServer(void);
void StopTcpServer(void);
void AcceptTcpSession(void);
int HandleTcpMessage(void);
void CloseTcpSession(void);
