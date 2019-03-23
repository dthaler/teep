/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include <string.h>
#include "tcps_string_t.h"
#include "TrustedApplication.h"

TrustedApplication::TrustedApplication(const char* id)
{
    int len = strlen(id);
    assert(len < sizeof(this->ID));
    strncpy(this->ID, id, len);
    this->ID[len] = 0;
}

TrustedApplication::~TrustedApplication()
{
}