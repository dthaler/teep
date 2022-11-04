// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include <dirent.h>
#include <filesystem>
#include <vector>
#include "t_cose/t_cose_common.h"
#include "TeepTamLib.h"
#include "TamKeys.h"
using namespace std;
#ifdef TEEP_USE_TEE
using namespace std::__fs;
#endif

#define TAM_SIGNING_PUBLIC_KEY_FILENAME "tam-public-key.pem"
#define TAM_SIGNING_PRIVATE_KEY_PAIR_FILENAME "tam-private-key-pair.pem"

struct t_cose_key g_tam_signing_key_pair;

teep_error_code_t TamGetSigningKeyPair(_Out_ struct t_cose_key* key_pair)
{
    *key_pair = g_tam_signing_key_pair;
    return TEEP_ERR_SUCCESS;
}

const unsigned char* g_TamDerCertificate = nullptr;
size_t g_TamDerCertificateSize = 0;

const unsigned char* GetTamDerCertificate(_Out_ size_t* pCertLen)
{
    if (g_TamDerCertificate == nullptr) {
        // Construct a self-signed DER certificate based on the COSE key.
        t_cose_key key_pair;
        teep_error_code_t teep_error = TamGetSigningKeyPair(&key_pair);
        if (teep_error != TEEP_ERR_SUCCESS) {
            return nullptr;
        }

        g_TamDerCertificate = GetDerCertificate(&key_pair, &g_TamDerCertificateSize);
    }

    *pCertLen = g_TamDerCertificateSize;
    return g_TamDerCertificate;
}

vector<struct t_cose_key> g_agent_key_pairs;

/* TODO: This is just a placeholder for a real implementation.
 * Currently we provide untrusted keys into the TAM.
 * In a real implementation, the TAM would instead either load
 * keys from a trusted location, or use sealed storage
 * (decrypting the contents inside the enclave).
 */
teep_error_code_t TamConfigureAgentKeys(_In_z_ const char* directory_name)
{
    g_agent_key_pairs.clear();

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
        g_agent_key_pairs.emplace_back(key_pair);
    }
    closedir(dir);
    return result;
}

/* Get the TEEP Agents' public keys to verify an incoming message against. */
vector<struct t_cose_key> TamGetTeepAgentKeys()
{
    return g_agent_key_pairs;
}

teep_error_code_t TamInitializeKeys(_In_z_ const char* dataDirectory, _Out_writes_opt_z_(256) char* publicKeyFilename)
{
    filesystem::path privateKeyPairFilenamePath = dataDirectory;
    privateKeyPairFilenamePath.append(TAM_SIGNING_PRIVATE_KEY_PAIR_FILENAME);

    filesystem::path publicKeyFilenamePath = dataDirectory;
    publicKeyFilenamePath.append(TAM_SIGNING_PUBLIC_KEY_FILENAME);

    teep_error_code_t result = teep_get_signing_key_pair(&g_tam_signing_key_pair,
        privateKeyPairFilenamePath.string().c_str(),
        publicKeyFilenamePath.string().c_str());
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }
    if (publicKeyFilename) {
        strcpy_s(publicKeyFilename, 256, publicKeyFilenamePath.string().c_str());
    }

    filesystem::path trustedKeysFilenamePath = dataDirectory;
    trustedKeysFilenamePath.append("trusted");

    result = TamConfigureAgentKeys(trustedKeysFilenamePath.string().c_str());
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }

    return TEEP_ERR_SUCCESS;
}
