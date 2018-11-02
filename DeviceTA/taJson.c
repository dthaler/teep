/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char* cjson_strcpy(char* dst, const char* src)
{
    int len = strlen(src);
    memcpy(dst, src, len + 1);
    return dst;
}

/* The cJSON library only calls this with format "%lg". */
int cjson_sscanf(const char* buffer, const char* format, double* value)
{
    char *endptr;
    if (strcmp(format, "%lg") != 0) {
        return 0;
    }
    *value = strtod(buffer, &endptr);
    if (*endptr != 0) {
        return 0;
    }
    return 1;
}

int cjson_sprintf(char* buffer, const char* format, ...)
{
    va_list arglist;
    va_start(arglist, format);

    /* We use 26 below which is the max size used by cJSON. */
    return vsnprintf(buffer, 26, format, arglist);
}

/* The cJSON library requires these, but always calls them safely. */
#define strcpy  cjson_strcpy
#define sprintf cjson_sprintf
#define sscanf  cjson_sscanf

/* Pull in external source code directly. */
#include "../external/cJSON/cJSON.c"
