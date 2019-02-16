/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

#define OTRP_URI L"http://localhost:54321/OTrP"
#define OTRP_PATH L"/OTrP"

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
