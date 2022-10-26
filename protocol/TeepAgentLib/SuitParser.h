// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once
#include <ostream>

teep_error_code_t TryProcessSuitEnvelope(UsefulBufC encoded, std::ostream& errorMessage);
