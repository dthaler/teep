// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include "UsefulBuf.h"
#include "Manifest.h"
#include <string.h>
#include <stdlib.h>
#include <dirent.h>

Manifest* Manifest::g_FirstManifest = nullptr;

Manifest::Manifest(
    teep_uuid_t component_id,
    _In_reads_(manifest_size) const char* manifest,
    size_t manifest_size,
    int is_required)
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

_Ret_maybenull_
Manifest* Manifest::First(void)
{
    return g_FirstManifest;
}

void Manifest::AddManifest(
    teep_uuid_t component_id,
    _In_reads_(manifest_content_size) const char* manifest_content,
    size_t manifest_content_size,
    int is_required)
{
    Manifest* manifest = new Manifest(component_id, manifest_content, manifest_content_size, is_required);
    manifest->Next = g_FirstManifest;
    g_FirstManifest = manifest;
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

_Ret_maybenull_
Manifest* Manifest::FindManifest(_In_ const UsefulBufC* component_id)
{
    for (Manifest* manifest = g_FirstManifest; manifest != nullptr; manifest = manifest->Next) {
        if (manifest->HasComponentId(component_id)) {
            return manifest;
        }
    }
    return nullptr;
}

void Manifest::ClearManifests(void)
{
    while (g_FirstManifest != nullptr) {
        Manifest* manifest = g_FirstManifest;
        g_FirstManifest = manifest->Next;
        delete manifest;
    }
}

static teep_error_code_t ConfigureManifest(
    _In_z_ const char* directory_name,
    _In_z_ const char* filename,
    int is_required)
{
    FILE* fp = NULL;
    char* manifest = NULL;
    size_t fullpathname_length = strlen(directory_name) + strlen(filename) + 2;
    char* fullpathname = (char*)malloc(fullpathname_length);
    if (fullpathname == NULL) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    sprintf_s(fullpathname, fullpathname_length, "%s/%s", directory_name, filename);

    teep_error_code_t result = TEEP_ERR_TEMPORARY_ERROR;
    do {
        /* Load content from file. */
        fp = fopen(fullpathname, "rb");
        if (fp == NULL) {
            break;
        }

        /* Get file size. */
        fseek(fp, 0L, SEEK_END);
        size_t manifest_size = ftell(fp);
        rewind(fp);

        manifest = (char*)malloc(manifest_size);
        if (manifest == NULL) {
            break;
        }

        size_t count = fread(manifest, manifest_size, (size_t)1, fp);
        if (count < 1) {
            break;
        }

        teep_uuid_t component_id;
        result = GetUuidFromFilename(filename, &component_id);
        if (result == TEEP_ERR_SUCCESS) {
            if (manifest_size > 2 && manifest[0] == 0xd8 && manifest[1] == 0x6b) {
                Manifest::AddManifest(component_id, manifest + 2, manifest_size - 2, is_required);
            }
            else {
                Manifest::AddManifest(component_id, manifest, manifest_size, is_required);
            }
        }
    } while (0);

    free(manifest);
    fclose(fp);
    free(fullpathname);
    return result;
}

/* TODO: This is just a placeholder for a real implementation.
 * Currently we provide untrusted manifests into the TAM.
 * In a real implementation, the TAM would instead either load
 * manifests from a trusted location, or use sealed storage
 * (decrypting the contents inside the TEE).
 */
teep_error_code_t TamConfigureManifests(
    _In_z_ const char* directory_name,
    int is_required)
{
    teep_error_code_t result = TEEP_ERR_SUCCESS;
    DIR* dir = opendir(directory_name);
    if (dir == NULL) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    for (;;) {
        struct dirent* dirent = readdir(dir);
        if (dirent == NULL) {
            break;
        }
        char* filename = dirent->d_name;
        size_t filename_length = strlen(filename);
        if (filename_length < 6 ||
            strcmp(filename + filename_length - 5, ".cbor") != 0) {
            continue;
        }
        result = ConfigureManifest(directory_name, filename, is_required);
        if (result != TEEP_ERR_SUCCESS) {
            break;
        }
    }
    closedir(dir);
    return result;
}
