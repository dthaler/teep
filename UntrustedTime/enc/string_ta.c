/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

char *strcpy(
    char *strDestination,
    const char *strSource)
{
    const char *s;
    char *d = strDestination;
    for (s = strSource; *s; s++) {
        *d = *s;
        d++;
    }
    *d = 0;
    return strDestination;
}

int strncasecmp(const char *string1,
    const char *string2,
    size_t count)
{
    int cmp;

    for (size_t i = 0; i < count; i++)
    {
        int a = string1[i];
        int b = string2[i];
        if (!a && !b)
        {
            return 0; /* Equal. */
        }
        cmp = tolower(a) - tolower(b);
        if (cmp != 0)
        {
            return cmp; /* Not equal. */
        }
    }
    return 0; /* Equal. */
}

char *strcat(
    char *strDestination,
    const char *strSource)
{
    strcpy(strDestination + strlen(strDestination), strSource);
    return strDestination;
}

int _vsnprintf(
    char *buffer,
    size_t count,
    const char *format,
    va_list argptr)
{
    // vsnprintf always writes a null terminator, even if it truncates the output.
    // It returns the number of characters that would be written, not counting the null character, if count were sufficiently large,
        // or -1 if an encoding error occurred.

        // _vsnprintf only writes a null terminator if there is room at the end.
        // It returns the number of characters actually written, or -1 if output has been truncated.

        int ret = vsnprintf(buffer, count, format, argptr);
    if ((count == 0) || ((size_t)ret > count - 1)) {
        // Output has been truncated.
        return -1;
    }
    return ret;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

int
ConvertStringToIPv4Integers(
    const char *addressString,
    const char *addressSscanfFormat,
    int        *addressByte0,
    int        *addressByte1,
    int        *addressByte2,
    int        *addressByte3)
{
    const char *currentPart;
    const char *p;
    int parts = 0;
    int addressByteValues[4] = { 0 };

    /*
    * This function gets called just from openssl's ipv4_from_asc(),
    * using the following sscanf format string.
    */
    assert(strcmp(addressSscanfFormat, "%d.%d.%d.%d") == 0);

    /* Implement inet_addr for SGX/OPTEE */
    for (currentPart = p = addressString; ; p++) {
        if (*p != 0 && *p != '.') {
            /* Find the next '.' character */
            continue;
        }

        addressByteValues[parts] = atoi(currentPart);
        parts++;

        if ((parts == ARRAY_SIZE(addressByteValues)) || (*p == 0)) {
            break;
        }

        currentPart = p + 1;
    }

    if (parts == 4) {
        *addressByte0 = addressByteValues[0];
        *addressByte1 = addressByteValues[1];
        *addressByte2 = addressByteValues[2];
        *addressByte3 = addressByteValues[3];
    } else {
        parts = 0;
    }

    return parts;
}