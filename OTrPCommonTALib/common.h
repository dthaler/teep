/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

int OTrPHandleMessage(void* sessionHandle, const char* key, const json_t* messageObject);

char *DecodeJWS(const json_t *jws, const json_t *jwk);