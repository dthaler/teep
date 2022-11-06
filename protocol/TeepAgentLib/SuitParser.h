// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once
#include <ostream>

teep_error_code_t TryProcessSuitEnvelope(UsefulBufC encoded, std::ostream& errorMessage);
void TeepAgentMakeManifestFilename(_Out_writes_(filename_len) char* filename, size_t filename_len, _In_reads_(buffer_len) const char* buffer, size_t buffer_len);
