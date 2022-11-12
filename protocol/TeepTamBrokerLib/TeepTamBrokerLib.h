// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once

// Other prototypes are the same as in the TEE.
#include "..\TeepTamLib\TeepTamLib.h"

#ifdef __cplusplus
extern "C" {
#endif

    int TamBrokerProcess(_In_z_ const wchar_t* tamUri);
    int StartTamBroker(_In_z_ const char* manifestDirectory, int simulated_tee);
    void StopTamBroker(void);

#ifdef __cplusplus
};
#endif
