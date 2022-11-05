// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include <openenclave/enclave.h>
#include "TeepCommonTALib_t.h"
#include "common.h"

teep_error_code_t teep_random(void* buffer, size_t length)
{
    oe_result_t result = oe_random(buffer, length);
    return (result == OE_OK) ? TEEP_ERR_SUCCESS : TEEP_ERR_TEMPORARY_ERROR;
}