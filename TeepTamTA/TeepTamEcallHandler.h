/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

json_t* GetTamEncryptionKey();

json_t* GetTamSigningKey();

const unsigned char* GetTamDerCertificate(size_t *pCertLen);

json_t* GetSha256Hash(void* buffer, int len);
