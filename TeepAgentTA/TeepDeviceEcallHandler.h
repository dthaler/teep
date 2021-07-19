// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once       

const unsigned char* GetAgentDerCertificate(size_t *pCertLen);
#ifdef TEEP_ENABLE_JSON
json_t* GetAgentSigningKey();
#endif

extern TrustedComponent* g_RequestedComponentList;
