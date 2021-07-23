// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include "common.h"

// Other prototypes are the same as in the TEE.
#include "..\TeepTamLib\TeepTamLib.h"

#ifdef __cplusplus
extern "C" {
#endif

    int TamBrokerProcess(_In_z_ const wchar_t* tamUri);

#ifdef __cplusplus
};
#endif
