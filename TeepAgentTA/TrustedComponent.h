/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once
class TrustedComponent
{
public:
    TrustedComponent(oe_uuid_t id);
    ~TrustedComponent();
    static int ConvertUUIDToString(char* buffer, size_t buffer_length, oe_uuid_t uuid);

    char Name[256];
    oe_uuid_t ID;

    TrustedComponent* Next;
};