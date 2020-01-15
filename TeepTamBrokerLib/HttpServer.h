/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

//#define TEEP_URI L"http://localhost:54321/TEEP"
#define TEEP_URI L"http://192.168.1.37:54321/TEEP"
#define TEEP_PATH L"/TEEP"

#ifdef __cplusplus
extern "C" {
#endif
int RunHttpServer(int argc, wchar_t** argv);

int StartHttpServer(void);
void StopHttpServer(void);
void AcceptHttpSession(void);
int HandleHttpMessage(void);
void CloseHttpSession(void);


#ifdef __cplusplus
};
#endif
