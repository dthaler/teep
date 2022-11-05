// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once
#include <map>
#include <vector>

teep_error_code_t TamConfigureAgentKeys(_In_z_ const char* directory_name);

std::vector<struct t_cose_key> TamGetTeepAgentKeys();

teep_error_code_t TamGetSigningKeyPairs(_Out_ std::map<teep_signature_kind_t, struct t_cose_key>& key_pairs);

void TamKeyPublicKey(teep_signature_kind_t kind, _Out_writes_opt_z_(256) char* publicKeyFilename);