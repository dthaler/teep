/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once       

const unsigned char* GetAgentDerCertificate(size_t *pCertLen);
#ifdef TEEP_ENABLE_JSON
json_t* GetAgentSigningKey();
#endif

extern TrustedComponent* g_RequestedComponentList;
