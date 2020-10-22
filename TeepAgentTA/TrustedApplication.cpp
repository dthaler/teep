/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include <string.h>
#include "TrustedApplication.h"

TrustedApplication::TrustedApplication(const char* id)
{
    size_t len = strlen(id);
    oe_assert(len < sizeof(this->ID));
    strncpy(this->ID, id, len);
    this->ID[len] = 0;
}

TrustedApplication::~TrustedApplication()
{
}