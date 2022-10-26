// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once
#include "qcbor/UsefulBuf.h"
#include "common.h"

class Manifest
{
public:
    static void AddManifest(teep_uuid_t component_id, const char* manifest_content, size_t manifest_content_size, int is_required);
    static Manifest* FindManifest(_In_ const UsefulBufC* component_id);
    static Manifest* First(void);
    static void ClearManifests(void);

    bool HasComponentId(_In_ const UsefulBufC* component_id);
    Manifest* Next;
    int IsRequired;
    UsefulBufC ManifestContents;

private:
    Manifest(teep_uuid_t component_id, const char* manifest, size_t manifest_size, int is_required);

    teep_uuid_t _component_id;

    static Manifest* g_FirstManifest;
};

teep_error_code_t TamConfigureManifests(
    _In_z_ const char* directory_name,
    int is_required);

