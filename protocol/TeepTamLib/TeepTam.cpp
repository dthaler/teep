// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <malloc.h>
#include <sys/types.h>
#include <dirent.h>
#include "TeepTamLib.h"
#include "Manifest.h"

#define TRUE 1
#define FALSE 0
#ifdef TEEP_USE_TEE
#define sprintf_s(dest, sz, ...) sprintf(dest, __VA_ARGS__)
#define _strdup strdup
int StartTamTABroker(const char* manifestDirectory, int simulate_tee);
void StopTamTABroker(void);
#define MAX_PATH 256
#endif

teep_error_code_t ConfigureManifest(const char* directory_name, const char* filename, int is_required)
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

        char* basename = _strdup(filename);
        if (basename != NULL) {
            size_t len = strlen(basename);
            if ((len > 5) && strcmp(basename + len - 5, ".cbor") == 0) {
                basename[len - 5] = 0;
            }

            teep_uuid_t component_id;
            int uuid[sizeof(teep_uuid_t)];
            sscanf_s(basename,
                "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                &uuid[0], &uuid[1], &uuid[2], &uuid[3], &uuid[4], &uuid[5], &uuid[6], &uuid[7],
                &uuid[8], &uuid[9], &uuid[10], &uuid[11], &uuid[12], &uuid[13], &uuid[14], &uuid[15]);
            for (size_t i = 0; i < sizeof(teep_uuid_t); i++) {
                component_id.b[i] = uuid[i];
            }

            Manifest::AddManifest(component_id, manifest, manifest_size, is_required);    
            result = TEEP_ERR_SUCCESS;
        }
        free(basename);
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
 * (decrypting the contents inside the enclave).
 */
teep_error_code_t ConfigureManifests(const char* directory_name, int is_required)
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