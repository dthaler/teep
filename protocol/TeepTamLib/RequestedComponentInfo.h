// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once
class RequestedComponentInfo
{
public:
    RequestedComponentInfo(UsefulBufC* componentId);
    ~RequestedComponentInfo();

    RequestedComponentInfo* Next;
    UsefulBufC ComponentId;
    uint64_t ManifestSequenceNumber;
    bool HaveBinary;
};

