// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <iostream>
#include <ostream>
#include "teep_protocol.h"

#ifdef ENABLE_OTRP
int OTrPHandleJsonMessage(void* sessionHandle, const char* message, unsigned int messageLength);
#endif
#ifdef TEEP_ENABLE_JSON
int TeepHandleJsonMessage(void* sessionHandle, const char* message, unsigned int messageLength);
#endif
teep_error_code_t TeepHandleCborMessage(void* sessionHandle, const char* message, unsigned int messageLength);
void HexPrintBuffer(const void* buffer, int length);

#if defined(ENABLE_OTRP) || defined(TEEP_ENABLE_JSON)
char *DecodeJWS(const json_t *jws, const json_t *jwk);

json_t* CreateNewJwkRS256(void);
json_t* CreateNewJwkR1_5(void);
json_t* CreateNewJwk(const char* alg);
json_t* CopyToJweKey(json_t* jwk1, const char* alg);

const unsigned char* GetDerCertificate(json_t* jwk, size_t *pCertificateSize);
#endif

#define UUID_LENGTH 16 // Size in bytes of a UUID (RFC 4122)

void report_type_error(std::ostream& s, const char* id, int expected_type, int actual_type);

#ifdef _DEBUG
#define REPORT_TYPE_ERROR(s, id, expected_type, item) { \
    report_type_error(s, id, expected_type, (item).uDataType); \
    report_type_error(std::cout, id, expected_type, (item).uDataType); \
}
#else
#define REPORT_TYPE_ERROR(s, id, expected_type, item) \
    report_type_error(s, id, expected_type, (item).uDataType);
#endif
