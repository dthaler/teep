/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once       

const unsigned char* GetAgentDerCertificate(size_t *pCertLen);
json_t* GetAgentSigningKey();

extern TrustedComponent* g_RequestedComponentList;
