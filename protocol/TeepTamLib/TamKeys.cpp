// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include <dirent.h>
#include <filesystem>
#include <vector>
#include "t_cose/t_cose_key.h"
#include "TeepTamLib.h"
#include "TamKeys.h"
using namespace std;
#ifdef TEEP_USE_TEE
using namespace std::__fs;
#endif

#define TAM_ES256_SIGNING_PUBLIC_KEY_FILENAME "tam-es256-public-key.pem"
#define TAM_ES256_SIGNING_PRIVATE_KEY_PAIR_FILENAME "tam-es256-private-key-pair.pem"

#define TAM_EDDSA_SIGNING_PUBLIC_KEY_FILENAME "tam-eddsa-public-key.pem"
#define TAM_EDDSA_SIGNING_PRIVATE_KEY_PAIR_FILENAME "tam-eddsa-private-key-pair.pem"

std::map<teep_signature_kind_t, struct t_cose_key> g_tam_signing_key_pairs;

teep_error_code_t TamGetSigningKeyPairs(_Out_ std::map<teep_signature_kind_t, struct t_cose_key>& key_pairs)
{
    key_pairs = g_tam_signing_key_pairs;
    return TEEP_ERR_SUCCESS;
}

map<teep_signature_kind_t, struct t_cose_key> g_agent_key_pairs;

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
        teep_signature_kind_t kind = (strstr(filename, "es256") != nullptr) ? TEEP_SIGNATURE_ES256 : TEEP_SIGNATURE_EDDSA;
        g_agent_key_pairs[kind] = key_pair;

        TeepLogMessage("TAM loaded TEEP agent key from %s\n", keyfile.c_str());
    }
    closedir(dir);
    return result;
}

/* Get the TEEP Agents' public keys to verify an incoming message against. */
map<teep_signature_kind_t, struct t_cose_key> TamGetTeepAgentKeys()
{
    return g_agent_key_pairs;
}

filesystem::path g_data_directory;

void TamGetPublicKey(teep_signature_kind_t kind, _Out_writes_opt_z_(256) char* publicKeyFilename)
{
    filesystem::path publicKeyFilenamePath = g_data_directory;

    switch (kind) {
    case TEEP_SIGNATURE_ES256:
        publicKeyFilenamePath.append(TAM_ES256_SIGNING_PUBLIC_KEY_FILENAME);
        break;
    case TEEP_SIGNATURE_EDDSA:
        publicKeyFilenamePath.append(TAM_EDDSA_SIGNING_PUBLIC_KEY_FILENAME);
        break;
    default:
        assert(FALSE);
    }

    strcpy_s(publicKeyFilename, 256, publicKeyFilenamePath.string().c_str());
}

static teep_error_code_t
_InitializeKey(teep_signature_kind_t signatureKind)
{
    filesystem::path privateKeyPairFilenamePath = g_data_directory;
    filesystem::path publicKeyFilenamePath = g_data_directory;

    switch (signatureKind) {
    case TEEP_SIGNATURE_ES256:
        privateKeyPairFilenamePath.append(TAM_ES256_SIGNING_PRIVATE_KEY_PAIR_FILENAME);
        publicKeyFilenamePath.append(TAM_ES256_SIGNING_PUBLIC_KEY_FILENAME);
        break;
    case TEEP_SIGNATURE_EDDSA:
        privateKeyPairFilenamePath.append(TAM_EDDSA_SIGNING_PRIVATE_KEY_PAIR_FILENAME);
        publicKeyFilenamePath.append(TAM_EDDSA_SIGNING_PUBLIC_KEY_FILENAME);
        break;
    default:
        return TEEP_ERR_PERMANENT_ERROR;
    }

    struct t_cose_key key_pair;
    teep_error_code_t result = teep_load_signing_key_pair(&key_pair,
        privateKeyPairFilenamePath.string().c_str(),
        publicKeyFilenamePath.string().c_str(),
        signatureKind);
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }
    g_tam_signing_key_pairs[signatureKind] = key_pair;
    return TEEP_ERR_SUCCESS;
}

teep_error_code_t TamInitializeKeys(_In_z_ const char* dataDirectory)
{
    g_data_directory = dataDirectory;

    teep_error_code_t result = _InitializeKey(TEEP_SIGNATURE_ES256);
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }
    result = _InitializeKey(TEEP_SIGNATURE_EDDSA);
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }

    filesystem::path trustedKeysFilenamePath = g_data_directory;
    trustedKeysFilenamePath.append("trusted");

    result = TamConfigureAgentKeys(trustedKeysFilenamePath.string().c_str());
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }

    return TEEP_ERR_SUCCESS;
}
