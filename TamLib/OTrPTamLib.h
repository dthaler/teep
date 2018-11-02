/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

int OTrPHandleMessage(
    _In_reads_(messageLength) const char *message,
    _In_ int messageLength);

int OTrPHandleConnect(void);
