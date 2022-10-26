// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include <dirent.h>
#include <filesystem>
#include "t_cose/t_cose_common.h"
#include "TeepAgentLib.h"
#include "AgentKeys.h"

#define TEEP_AGENT_SIGNING_PRIVATE_KEY_PAIR_FILENAME "agent-private-key-pair.pem"
#define TEEP_AGENT_SIGNING_PUBLIC_KEY_FILENAME "agent-public-key.pem"

struct t_cose_key g_teep_agent_signing_key_pair;

teep_error_code_t TeepAgentGetSigningKeyPair(struct t_cose_key* key_pair)
{
    *key_pair = g_teep_agent_signing_key_pair;
    return TEEP_ERR_SUCCESS;
}

std::vector<struct t_cose_key> g_tam_key_pairs;

/* TODO: This is just a placeholder for a real implementation.
 * Currently we provide untrusted keys into the TAM.
 * In a real implementation, the TAM would instead either load
 * keys from a trusted location, or use sealed storage
 * (decrypting the contents inside the enclave).
 */
teep_error_code_t TeepAgentConfigureTamKeys(_In_z_ const char* directory_name)
{
    g_tam_key_pairs.clear();

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

        // Compose path to file.
        char* filename = dirent->d_name;
        size_t filename_length = strlen(filename);
        if (filename_length < 5 ||
            strcmp(filename + filename_length - 4, ".pem") != 0) {
            continue;
        }
        std::string keyfile = std::string(directory_name) + "/" + filename;

        // Load public key from file.
        struct t_cose_key key_pair;
        result = teep_get_verifying_key_pair(&key_pair, keyfile.c_str());
        if (result != TEEP_ERR_SUCCESS) {
            break;
        }
        g_tam_key_pairs.emplace_back(key_pair);
    }
    closedir(dir);
    return result;
}

/* Get the TEEP Agents' public keys to verify an incoming message against. */
std::vector<struct t_cose_key> TeepAgentGetTamKeys()
{
    return g_tam_key_pairs;
}

teep_error_code_t TeepAgentInitializeKeys(_In_z_ const char* dataDirectory, _Out_writes_opt_z_(256) char* publicKeyFilename)
{
    std::filesystem::path privateKeyPairFilenamePath = dataDirectory;
    privateKeyPairFilenamePath.append(TEEP_AGENT_SIGNING_PRIVATE_KEY_PAIR_FILENAME);

    std::filesystem::path publicKeyFilenamePath = dataDirectory;
    publicKeyFilenamePath.append(TEEP_AGENT_SIGNING_PUBLIC_KEY_FILENAME);

    teep_error_code_t result = teep_get_signing_key_pair(&g_teep_agent_signing_key_pair,
        privateKeyPairFilenamePath.string().c_str(),
        publicKeyFilenamePath.string().c_str());
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }
    if (publicKeyFilename) {
        strcpy_s(publicKeyFilename, 256, publicKeyFilenamePath.string().c_str());
    }

    std::filesystem::path trustedKeysFilenamePath = dataDirectory;
    trustedKeysFilenamePath.append("trusted");

    result = TeepAgentConfigureTamKeys(trustedKeysFilenamePath.string().c_str());
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }

    return TEEP_ERR_SUCCESS;
}