// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stddef.h>
#include <stdlib.h>

#include <TrustedOpenssl.h>

char *getenv(const char *varname)
{
    (void)varname;
    return NULL;
}

/*
void SetLastError(DWORD dwErrCode)
{
    (void)dwErrCode;
}
*/
