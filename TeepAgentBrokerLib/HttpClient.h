/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    const char* SendTeepMessage(TeepSession* session, char** pResponseMediaType, int* pResponseLength);

#ifdef __cplusplus
};
#endif
