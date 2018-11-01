/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <string.h>
#include "OTrPTamLib.h"
#include "OTrPTam_u.h"
#include "../cJSON/cJSON.h"

sgx_enclave_id_t g_ta_eid = 0;

int OTrPHandleClientMessage(
    const char *message,
    int messageLength)
{
    int err = 0;
    sgx_status_t sgxStatus = ecall_ProcessOTrPMessage(g_ta_eid, &err, message, messageLength);
    if (sgxStatus != SGX_SUCCESS) {
        return sgxStatus;
    }
    return err;
}

int OTrPHandleClientConnect(void)
{
    int err = 0;
    sgx_status_t sgxStatus = ecall_ProcessOTrPClientConnect(g_ta_eid, &err);
    if (sgxStatus != SGX_SUCCESS) {
        return sgxStatus;
    }
    return err;
}