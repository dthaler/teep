// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include "qcbor/UsefulBuf.h"
#include "RequestedComponentInfo.h"

RequestedComponentInfo::RequestedComponentInfo(_In_ const UsefulBufC* componentId)
{
    if (componentId != nullptr) {
        this->ComponentId = *componentId;
    } else {
        this->ComponentId.len = 0;
        this->ComponentId.ptr = nullptr;
    }
    this->ManifestSequenceNumber = 0;
    this->HaveBinary = false;
    this->Next = nullptr;
}

RequestedComponentInfo::~RequestedComponentInfo()
{
    if (this->Next != nullptr) {
        delete this->Next;
    }
}
