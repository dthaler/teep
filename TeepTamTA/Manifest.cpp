/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include "UsefulBuf.h"
#include "TeepTam_t.h"
#include "Manifest.h"
#include <string.h>
#include <stdlib.h>

// TODO: support more than one manifest
Manifest* Manifest::g_Manifest = nullptr;

Manifest::Manifest(oe_uuid_t component_id, const char* manifest, size_t manifest_size)
{
    this->_manifest_size = 0;
    this->_manifest = nullptr;
    this->_component_id = component_id;
    this->Next = nullptr;

    void* buffer = malloc(manifest_size);
    if (buffer != nullptr) {
        this->_manifest = (const char*)buffer;
        memcpy(buffer, manifest, manifest_size);
        this->_manifest_size = manifest_size;
    }
}

void Manifest::AddManifest(oe_uuid_t component_id, const char* manifest_content, size_t manifest_content_size)
{
    Manifest* manifest = new Manifest(component_id, manifest_content, manifest_content_size);
    manifest->Next = g_Manifest;
    g_Manifest = manifest;

}

const char* Manifest::GetManifest(UsefulBufC* component_id, size_t* manifest_size)
{
    for (Manifest* manifest = g_Manifest; manifest != nullptr; manifest = manifest->Next) {
        if (sizeof(g_Manifest->_component_id) != component_id->len) {
            continue;
        }
        if (memcmp(&g_Manifest->_component_id, component_id->ptr, component_id->len) != 0) {
            continue;
        }
        *manifest_size = g_Manifest->_manifest_size;
        return g_Manifest->_manifest;
    }
    return nullptr;
}

void ecall_ConfigureManifest(oe_uuid_t component_id, const char* manifest, size_t manifest_size)
{
    Manifest::AddManifest(component_id, manifest, manifest_size);
}