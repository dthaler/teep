// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#define TEEP_PATH L"/TEEP"

#ifdef __cplusplus
extern "C" {
#endif
int RunHttpServer(int argc, const wchar_t** argv);

int StartHttpServer(void);
void StopHttpServer(void);
void AcceptHttpSession(void);
int HandleHttpMessage(void);
void CloseHttpSession(void);


#ifdef __cplusplus
};
#endif
