/* Copyright Microsoft Corporation */
#include "UntrustedTimeTALib.h"
#include "../UntrustedTime/enc/time.h"
#include <TrustedOpenssl.h>

struct tm *localtime(const time_t *timer)
{
    __time64_t t64 = *timer;
    return _localtime64(&t64);
}

struct tm *gmtime_r(const time_t *timer, struct tm *result)
{
    __time64_t t64 = *timer;
    *result = *_gmtime64(&t64);
    return result;
}
