/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

#define OTRP_URI L"http://localhost:54321/OTRP"
#define OTRP_PATH L"/OTRP"

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
