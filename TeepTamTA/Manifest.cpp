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

    void* buffer = malloc(manifest_size);
    if (buffer != nullptr) {
        this->_manifest = (const char*)buffer;
        memcpy(buffer, manifest, manifest_size);
        this->_manifest_size = manifest_size;
    }
}

void Manifest::AddManifest(oe_uuid_t component_id, const char* manifest, size_t manifest_size)
{
    g_Manifest = new Manifest(component_id, manifest, manifest_size);
}

const char* Manifest::GetManifest(UsefulBufC* component_id, size_t* manifest_size)
{
    if (sizeof(g_Manifest->_component_id) != component_id->len) {
        return nullptr;
    }
    if (memcmp(&g_Manifest->_component_id, component_id->ptr, component_id->len) != 0) {
        return nullptr;
    }
    *manifest_size = g_Manifest->_manifest_size;
    return g_Manifest->_manifest;
}

void ecall_ConfigureManifest(oe_uuid_t component_id, const char* manifest, size_t manifest_size)
{
    Manifest::AddManifest(component_id, manifest, manifest_size);
}