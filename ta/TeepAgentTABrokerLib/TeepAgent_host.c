// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <openenclave/host.h>
#include "TeepAgent_u.h"

extern oe_enclave_t* g_ta_eid;

oe_result_t create_TeepAgent_enclave(const char* enclave_name, int simulated_tee, oe_enclave_t** out_enclave)
{
    oe_enclave_t* enclave = NULL;
    uint32_t enclave_flags = 0;
    oe_result_t result;

    *out_enclave = NULL;

    // Create the enclave
#ifdef _DEBUG
    enclave_flags |= OE_ENCLAVE_FLAG_DEBUG;
#endif
    if (simulated_tee) {
        enclave_flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }
    result = oe_create_TeepAgent_enclave(
        enclave_name,
        OE_ENCLAVE_TYPE_AUTO,
        enclave_flags,
        NULL,
        0,
        &enclave);
    if (result != OE_OK)
    {
        return result;
    }

    *out_enclave = enclave;
    return OE_OK;
}

int StartAgentTABroker(int simulated_tee)
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result = create_TeepAgent_enclave(
#ifdef OE_USE_OPTEE
        "548e7daa-9a94-4826-b054-daa20dcc9c9c",
#else
        "TeepAgentTA.elf.signed",
#endif
        simulated_tee,
        &enclave);
    g_ta_eid = enclave;
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "oe_create_enclave(): result=%u (%s)\n",
            result,
            oe_result_str(result));
        return result;
    }

    return 0;
}

void StopAgentTABroker(void)
{
    /* Clean up the enclave if we created one. */
    if (g_ta_eid != NULL)
    {
        oe_terminate_enclave(g_ta_eid);
        g_ta_eid = NULL;
    }
}
