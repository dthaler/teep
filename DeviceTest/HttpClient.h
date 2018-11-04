/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    const char* ConnectToTam(const char* serverName);
    const char* HandleHttpResponse(const char* message, const char* uri);

#ifdef __cplusplus
};
#endif
