/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <string.h>
#include "OTrPTamBrokerLib.h"
#include "OTrPTam_u.h"

oe_enclave_t* g_ta_eid = NULL;

int OTrPHandleMessage(
    const char *message,
    int messageLength)
{
    int err = 0;
    oe_result_t result = ecall_ProcessOTrPMessage(g_ta_eid, &err, message, messageLength);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

int OTrPHandleConnect(void)
{
    int err = 0;
    oe_result_t result = ecall_ProcessOTrPConnect(g_ta_eid, &err);
    if (result != OE_OK) {
        return result;
    }
    return err;
}