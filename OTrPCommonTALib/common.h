/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

int OTrPHandleMessage(void* sessionHandle, const char* key, const json_t* messageObject);

char *DecodeJWS(const json_t *jws, const json_t *jwk);

json_t* CreateNewJwkRS256(void);
json_t* CreateNewJwkR1_5(void);
json_t* CreateNewJwk(const char* alg);
json_t* CopyToJweKey(json_t* jwk1, const char* alg);