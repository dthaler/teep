#define _CRT_SECURE_NO_WARNINGS
#include <openenclave/host.h>
#include "TeepTam_u.h"

extern oe_enclave_t* g_ta_eid;

oe_result_t create_TeepTam_enclave(const char* enclave_name, oe_enclave_t** out_enclave)
{
    oe_enclave_t* enclave = NULL;
    uint32_t enclave_flags = 0;
    oe_result_t result;

    *out_enclave = NULL;

    // Create the enclave
#ifdef _DEBUG
    enclave_flags |= OE_ENCLAVE_FLAG_DEBUG;
#endif
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

/* This is just a placeholder for a real implementation. */
oe_result_t ConfigureManifests(oe_enclave_t* enclave)
{
    FILE* fp = NULL;
    char* manifest = NULL;
    oe_result_t result = OE_FAILURE;

    do {
        /* Load content from manifests/ta1.cbor sample file. */
        fp = fopen("../../../manifests/ta1.cbor", "rb");
        if (fp == NULL) {
            break;
        }

        /* Get file size. */
        fseek(fp, 0L, SEEK_END);
        size_t manifest_size = ftell(fp);
        rewind(fp);

        manifest = malloc(manifest_size);
        if (manifest == NULL) {
            break;
        }

        size_t count = fread(manifest, manifest_size, (size_t)1, fp);
        if (count < 1) {
            break;
        }

        result = ecall_ConfigureManifest(enclave, "ta1", manifest, manifest_size);
    } while (0);

    free(manifest);
    fclose(fp);
    return result;
}

int StartTamBroker(void)
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result = create_TeepTam_enclave(
#ifdef OE_USE_OPTEE
        "94d75f35-541b-4ef0-a3f0-e8e87f29243c",
#else
        "TeepTamTA.elf.signed",
#endif
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

    result = ecall_Initialize(enclave);
    if (result != OE_OK) {
        return result;
    }

    result = ConfigureManifests(enclave);
    return result;
}

void StopTamBroker(void)
{
    /* Clean up the enclave if we created one. */
    if (g_ta_eid != NULL)
    {
        oe_terminate_enclave(g_ta_eid);
        g_ta_eid = NULL;
    }
}
