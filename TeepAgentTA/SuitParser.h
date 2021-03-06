/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once
#include <ostream>

teep_error_code_t TryProcessSuitEnvelope(UsefulBufC encoded, std::ostream& errorMessage);