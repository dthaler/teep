// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
class RequestedComponentInfo
{
public:
    RequestedComponentInfo(UsefulBufC* componentId);
    ~RequestedComponentInfo();

    RequestedComponentInfo* Next;
    UsefulBufC ComponentId;
    int ManifestSequenceNumber;
    bool HaveBinary;
};

