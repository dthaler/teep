// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <vector>

teep_error_code_t TeepAgentConfigureTamKeys(_In_z_ const char* directory_name);

std::vector<struct t_cose_key> TeepAgentGetTamKeys();

teep_error_code_t TeepAgentGetSigningKeyPair(struct t_cose_key* key_pair);