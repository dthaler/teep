/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#include "TeepAgent_u.h"

void ocall_print(const char* message)
{
    printf("%s", message);
}
