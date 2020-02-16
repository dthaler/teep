/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

#include <stdint.h>

typedef int64_t __time64_t;

#if !defined(_TIME_T_DEFINED_) && !defined(__time_t_defined)
# ifdef _USE_32BIT_TIME_T
typedef int32_t __time32_t;
typedef __time32_t time_t;
# else
typedef __time64_t time_t;
# endif
# define _TIME_T_DEFINED_
# define __time_t_defined
#endif

struct tm* _localtime64(const __time64_t *timer);
struct tm* _gmtime64(const __time64_t *timer64);
