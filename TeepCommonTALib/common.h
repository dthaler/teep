/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

int OTrPHandleJsonMessage(void* sessionHandle, const char* message, unsigned int messageLength);
int TeepHandleJsonMessage(void* sessionHandle, const char* message, unsigned int messageLength);
int TeepHandleCborMessage(void* sessionHandle, const char* message, unsigned int messageLength);
void HexPrintBuffer(const void* buffer, int length);

char *DecodeJWS(const json_t *jws, const json_t *jwk);

json_t* CreateNewJwkRS256(void);
json_t* CreateNewJwkR1_5(void);
json_t* CreateNewJwk(const char* alg);
json_t* CopyToJweKey(json_t* jwk1, const char* alg);

const unsigned char* GetDerCertificate(json_t* jwk, size_t *pCertificateSize);

#define UUID_LENGTH 16 // Size in bytes of a UUID (RFC 4122)
