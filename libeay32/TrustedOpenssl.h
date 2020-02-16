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

void RAND_screen(void);

/* Hack: Rename openssl's ECDSA_verify, to avoid conflicting with RIoT's ECDSA_verify */
#define ECDSA_verify openssl_ECDSA_verify
