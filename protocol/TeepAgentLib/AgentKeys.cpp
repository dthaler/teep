// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include <dirent.h>
#include <filesystem>
#include <vector>
#include "t_cose/t_cose_key.h"
#include "TeepAgentLib.h"
#include "AgentKeys.h"
using namespace std;
#ifdef TEEP_USE_TEE
using namespace std::__fs;
#endif

#define TEEP_AGENT_ES256_SIGNING_PRIVATE_KEY_PAIR_FILENAME "agent-es256-private-key-pair.pem"
#define TEEP_AGENT_ES256_SIGNING_PUBLIC_KEY_FILENAME "agent-es256-public-key.pem"

#define TEEP_AGENT_EDDSA_SIGNING_PRIVATE_KEY_PAIR_FILENAME "agent-eddsa-private-key-pair.pem"
#define TEEP_AGENT_EDDSA_SIGNING_PUBLIC_KEY_FILENAME "agent-eddsa-public-key.pem"

struct t_cose_key g_teep_agent_signing_key_pair;
teep_signature_kind_t g_teep_agent_signing_key_kind = TEEP_SIGNATURE_BOTH; // Neither.

void TeepAgentGetSigningKeyPair(_Out_ struct t_cose_key* keyPair, _Out_ teep_signature_kind_t* kind)
{
    *keyPair = g_teep_agent_signing_key_pair;
    *kind = g_teep_agent_signing_key_kind;
}

map<teep_signature_kind_t,struct t_cose_key> g_tam_key_pairs;

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
        string keyfile = string(directory_name) + "/" + filename;

        // Load public key from file.
        struct t_cose_key key_pair;
        result = teep_get_verifying_key_pair(&key_pair, keyfile.c_str());
        if (result != TEEP_ERR_SUCCESS) {
            break;
        }
        teep_signature_kind_t kind = (strstr(filename, "es256") != nullptr) ? TEEP_SIGNATURE_ES256 : TEEP_SIGNATURE_EDDSA;
        g_tam_key_pairs[kind] = key_pair;
    }
    closedir(dir);
    return result;
}

/* Get the TEEP Agents' public keys to verify an incoming message against. */
map<teep_signature_kind_t, struct t_cose_key> TeepAgentGetTamKeys()
{
    return g_tam_key_pairs;
}

teep_error_code_t TeepAgentInitializeKeys(_In_z_ const char* dataDirectory,
    teep_signature_kind_t signatureKind, _Out_writes_opt_z_(256) char* publicKeyFilename)
{
    filesystem::path privateKeyPairFilenamePath = dataDirectory;
    filesystem::path publicKeyFilenamePath = dataDirectory;

    switch (signatureKind) {
    case TEEP_SIGNATURE_ES256:
        privateKeyPairFilenamePath.append(TEEP_AGENT_ES256_SIGNING_PRIVATE_KEY_PAIR_FILENAME);
        publicKeyFilenamePath.append(TEEP_AGENT_ES256_SIGNING_PUBLIC_KEY_FILENAME);
        break;
    case TEEP_SIGNATURE_EDDSA:
        privateKeyPairFilenamePath.append(TEEP_AGENT_EDDSA_SIGNING_PRIVATE_KEY_PAIR_FILENAME);
        publicKeyFilenamePath.append(TEEP_AGENT_EDDSA_SIGNING_PUBLIC_KEY_FILENAME);
        break;
    default: return TEEP_ERR_PERMANENT_ERROR;
    }

    teep_error_code_t result = teep_load_signing_key_pair(&g_teep_agent_signing_key_pair,
        privateKeyPairFilenamePath.string().c_str(),
        publicKeyFilenamePath.string().c_str(),
        signatureKind);
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }
    g_teep_agent_signing_key_kind = signatureKind;
    if (publicKeyFilename) {
        strcpy_s(publicKeyFilename, 256, publicKeyFilenamePath.string().c_str());
    }

    filesystem::path trustedKeysFilenamePath = dataDirectory;
    trustedKeysFilenamePath.append("trusted");

    result = TeepAgentConfigureTamKeys(trustedKeysFilenamePath.string().c_str());
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }

    return TEEP_ERR_SUCCESS;
}