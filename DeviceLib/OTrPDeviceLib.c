/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include "OTrPDeviceLib.h"
#include "OTrPDevice_u.h"

sgx_enclave_id_t g_ta_eid = 0;

int OTrPHandleMessage(const char *message, int messageLength)
{
    int err = 0;
    sgx_status_t sgxStatus = ecall_ProcessOTrPMessage(g_ta_eid, &err, message, messageLength);
    if (sgxStatus != SGX_SUCCESS) {
        return sgxStatus;
    }
    return err;
}

int OTrPHandleConnect(void)
{
    int err = 0;
    sgx_status_t sgxStatus = ecall_ProcessOTrPConnect(g_ta_eid, &err);
    if (sgxStatus != SGX_SUCCESS) {
        return sgxStatus;
    }
    return err;
}
