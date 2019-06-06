/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

/* Avoid confusing openssl */
#if defined(_WIN32)
#undef _WIN32
#endif

#include "UntrustedTimeTALib.h"
#include <stdio.h>
#define OE_NO_SAL 1
#include <openenclave/enclave.h>
#define GETPID_IS_MEANINGLESS

#include <string.h>
#include <time.h>

#if defined(OE_USE_OPTEE)
#include <tee_api.h>
#include "optee/tcps_ctype_optee_t.h"
#else
unsigned long _lrotl(unsigned long val, int shift);
unsigned long _lrotr(unsigned long value, int shift);
#endif

#if 0
#include "tcps_stdlib_t.h"
#include "tcps_stdio_t.h"
#include "tcps_time_t.h"
#include "tcps_string_t.h"
#else
typedef __int64 __time64_t;
struct tm* _gmtime64(const __time64_t *timer);
#endif

void RAND_screen(void);

/* Hack: Rename openssl's ECDSA_verify, to avoid conflicting with RIoT's ECDSA_verify */
#define ECDSA_verify openssl_ECDSA_verify
