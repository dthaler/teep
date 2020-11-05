/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
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

