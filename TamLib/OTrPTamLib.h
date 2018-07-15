/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

int OTrPHandleClientMessage(
    const char *inputMessage,
    int inputMessageLength,
    char** pOutputMessage,
    int* pOutputMessageLength);

int OTrPHandleClientConnect(
    char** pMessage,
    int* pMessageLength);
