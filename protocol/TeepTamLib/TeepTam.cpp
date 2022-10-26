// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include <malloc.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <vector>
#include "TeepTamLib.h"
#include "TamKeys.h"
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

teep_error_code_t TamLoadConfiguration(_In_z_ const char* dataDirectory)
{
    std::string requiredManifestPath = std::string(dataDirectory) + "/manifests/required";
    teep_error_code_t result = TamConfigureManifests(
        requiredManifestPath.c_str(),
        true);
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }

    std::string optionalManifestPath = std::string(dataDirectory) + "/manifests/optional";
    result = TamConfigureManifests(
        optionalManifestPath.c_str(),
        false);
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }

    return TEEP_ERR_SUCCESS;
}