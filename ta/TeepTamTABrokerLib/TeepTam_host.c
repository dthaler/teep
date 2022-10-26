// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#define _CRT_SECURE_NO_WARNINGS
#include <openenclave/host.h>
#include "TeepTam_u.h"

extern oe_enclave_t* g_ta_eid;

oe_result_t create_TeepTam_enclave(const char* enclave_name, int simulated_tee, oe_enclave_t** out_enclave)
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
    result = oe_create_TeepTam_enclave(
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

int StartTamTABroker(_In_z_ const char* manifestDirectory, int simulate_tee)
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result = create_TeepTam_enclave(
#ifdef OE_USE_OPTEE
        "94d75f35-541b-4ef0-a3f0-e8e87f29243c",
#else
        "TeepTamTA.elf.signed",
#endif
        simulate_tee,
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

void StopTamTABroker(void)
{
    /* Clean up the enclave if we created one. */
    if (g_ta_eid != NULL)
    {
        oe_terminate_enclave(g_ta_eid);
        g_ta_eid = NULL;
    }
}
