#pragma once
/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */

int OTrPHandleMessage(const char* key, const json_t* messageObject);

char *DecodeJWS(const json_t *jws, const json_t *jwk);