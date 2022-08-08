// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "UsefulBuf.h"
#include "Manifest.h"
#include <string.h>
#include <stdlib.h>

Manifest* Manifest::g_Manifest = nullptr;

Manifest::Manifest(teep_uuid_t component_id, const char* manifest, size_t manifest_size, int is_required)
{
    this->ManifestContents.len  = 0;
    this->ManifestContents.ptr = nullptr;
    this->_component_id = component_id;
    this->IsRequired = is_required;
    this->Next = nullptr;

    void* buffer = malloc(manifest_size);
    if (buffer != nullptr) {
        this->ManifestContents.ptr = buffer;
        memcpy(buffer, manifest, manifest_size);
        this->ManifestContents.len = manifest_size;
    }
}

Manifest* Manifest::First(void)
{
    return g_Manifest;
}

void Manifest::AddManifest(teep_uuid_t component_id, const char* manifest_content, size_t manifest_content_size, int is_required)
{
    Manifest* manifest = new Manifest(component_id, manifest_content, manifest_content_size, is_required);
    manifest->Next = g_Manifest;
    g_Manifest = manifest;
}

bool Manifest::HasComponentId(_In_ const UsefulBufC* component_id)
{
    if (sizeof(_component_id) != component_id->len) {
        return false;
    }
    if (memcmp(&_component_id, component_id->ptr, component_id->len) != 0) {
        return false;
    }
    return true;
}

Manifest* Manifest::FindManifest(_In_ const UsefulBufC* component_id)
{
    for (Manifest* manifest = g_Manifest; manifest != nullptr; manifest = manifest->Next) {
        if (manifest->HasComponentId(component_id)) {
            return manifest;
        }
    }
    return nullptr;
}
