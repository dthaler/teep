/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once
#include <stddef.h>
#include <stdarg.h>

#define stderr NULL
#define FILE   SGX_FILE
#define fopen  sgx_fopen_auto_key
#define fclose sgx_fclose
#define fread  sgx_fread
#define fwrite sgx_fwrite
#define fflush sgx_fflush
#define ftell  sgx_ftell
#define fseek  sgx_fseek
#define feof   sgx_feof
#define ferror sgx_ferror

int strncasecmp(
    const char *string1,
    const char *string2,
    size_t count);

int _vsnprintf(
    char* buffer,
    size_t count,
    const char* format,
    va_list argptr)
#ifdef USE_OPTEE
    __attribute__((format(printf, 3, 0)))
#endif
    ;

/* sscanf is used just by openssl's ipv4_from_asc() */
int
ConvertStringToIPv4Integers(
    const char *addressString,
    const char *addressSscanfFormat,
    int        *addressByte0,
    int        *addressByte1,
    int        *addressByte2,
    int        *addressByte3);

#define sscanf(addressString, addressSscanfFormat, addressByte0, addressByte1, addressByte2, addressByte3)  \
ConvertStringToIPv4Integers(addressString, addressSscanfFormat, addressByte0, addressByte1, addressByte2, addressByte3)