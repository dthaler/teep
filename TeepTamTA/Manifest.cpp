/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include "TeepTam_t.h"
#include "Manifest.h"
#include <string.h>

Manifest* Manifest::g_Manifest = nullptr;

Manifest::Manifest(const char* taid, const char* manifest, size_t manifest_size)
{
    this->_manifest_size = 0;
    this->_manifest = nullptr;
    this->_taid = nullptr;

    void* buffer = malloc(manifest_size);
    if (buffer != nullptr) {
        this->_manifest = (const char*)buffer;
        memcpy(buffer, manifest, manifest_size);
        this->_manifest_size = manifest_size;
        this->_taid = strdup(taid);
    }
}

void Manifest::AddManifest(const char* taid, const char* manifest, size_t manifest_size)
{
    g_Manifest = new Manifest(taid, manifest, manifest_size);
}

const char* Manifest::GetManifest(const char* taid, size_t* manifest_size)
{
    if (strcmp(g_Manifest->_taid, taid) == 0) {
        *manifest_size = g_Manifest->_manifest_size;
        return g_Manifest->_manifest;
    }
    return nullptr;
}

void ecall_ConfigureManifest(const char* taid, const char* manifest, size_t manifest_size)
{
    Manifest::AddManifest(taid, manifest, manifest_size);
}