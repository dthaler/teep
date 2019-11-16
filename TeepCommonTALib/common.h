/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

#define OTRP_JSON_MEDIA_TYPE "application/otrp+json"
#define TEEP_JSON_MEDIA_TYPE "application/teep+json"

int OTrPHandleMessage(void* sessionHandle, const char* key, const json_t* messageObject);
int TeepHandleMessage(void* sessionHandle, const char* key, const json_t* messageObject);

char *DecodeJWS(const json_t *jws, const json_t *jwk);

json_t* CreateNewJwkRS256(void);
json_t* CreateNewJwkR1_5(void);
json_t* CreateNewJwk(const char* alg);
json_t* CopyToJweKey(json_t* jwk1, const char* alg);

const unsigned char* GetDerCertificate(json_t* jwk, size_t *pCertificateSize);
