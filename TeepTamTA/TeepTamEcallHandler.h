// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#ifdef TEEP_ENABLE_JSON
json_t* GetTamEncryptionKey();

json_t* GetTamSigningKey();

json_t* GetSha256Hash(void* buffer, int len);
#endif

const unsigned char* GetTamDerCertificate(size_t *pCertLen);
