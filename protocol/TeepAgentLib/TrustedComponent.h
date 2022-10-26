// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once
#include "common.h"

class TrustedComponent
{
public:
    TrustedComponent(teep_uuid_t id);
    ~TrustedComponent();
    static int ConvertUUIDToString(char* buffer, size_t buffer_length, teep_uuid_t uuid);

    char Name[256];
    teep_uuid_t ID;

    TrustedComponent* Next;
};
