/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/bits/stdio.h>
#include "UntrustedTimeTALib.h"

#if 0
char *fgets(
    char *str,
    int n,
    FILE *stream)
{
    size_t sz = sgx_fread(str, 1, n, stream);
    if (sgx_ferror(stream)) {
        return NULL;
    }
    return str;
}
#endif

int vfprintf(
    FILE *stream,
    const char *format,
    va_list argptr)
{
    int len;
    char* buffer;
    int written;

    len = _vsnprintf(NULL, 0, format, argptr);
    if (len < 0) {
        return -1;
    }

    buffer = malloc(len + 1);
    if (buffer == NULL) {
        return -1;
    }
    len = _vsnprintf(buffer, len, format, argptr);
    written = fwrite(buffer, 1, len, stream);
    free(buffer);

    return written;
}

int fprintf(FILE* const _Stream, char const* const _Format, ...)
{
    va_list _ArgList;
    va_start(_ArgList, _Format);

    return vfprintf(_Stream, _Format, _ArgList);
}
