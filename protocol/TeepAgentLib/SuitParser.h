// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once
#include <filesystem>
#include <ostream>
using namespace std;
#ifdef TEEP_USE_TEE
using namespace std::__fs;
#endif

teep_error_code_t TryProcessSuitEnvelope(UsefulBufC encoded, std::ostream& errorMessage);
void TeepAgentMakeManifestFilename(_Out_ filesystem::path& filename, _In_reads_(buffer_len) const char* buffer, size_t buffer_len);
