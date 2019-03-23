/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once
class TrustedApplication
{
public:
    TrustedApplication(const char* id);
    ~TrustedApplication();

    char Name[256];
    char ID[256];

    TrustedApplication* Next;
};