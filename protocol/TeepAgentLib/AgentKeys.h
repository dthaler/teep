// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once
#include <vector>

teep_error_code_t TeepAgentConfigureTamKeys(_In_z_ const char* directory_name);

std::vector<struct t_cose_key> TeepAgentGetTamKeys();

void TeepAgentGetSigningKeyPair(_Out_ struct t_cose_key* keyPair, _Out_ teep_signature_kind_t* kind);