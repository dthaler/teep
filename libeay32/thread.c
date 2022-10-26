// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT

#include <stddef.h>
#include <stdlib.h>

#include <TrustedOpenssl.h>

#ifdef OE_USE_SGX
char *getenv(const char *varname)
{
    (void)varname;
    return NULL;
}
#endif

/*
void SetLastError(DWORD dwErrCode)
{
    (void)dwErrCode;
}
*/
