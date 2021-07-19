// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <stdio.h>
#include "TeepAgent_u.h"

void ocall_print(const char* message)
{
    printf("%s", message);
}
