// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <vector>

teep_error_code_t TamConfigureAgentKeys(_In_z_ const char* directory_name);

std::vector<struct t_cose_key> TamGetTeepAgentKeys();

teep_error_code_t TamGetSigningKeyPair(_Out_ struct t_cose_key* key_pair);