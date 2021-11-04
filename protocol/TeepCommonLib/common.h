// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

// This file has defines that are in common between
// the TAM and the TEEP Agent.

#include "teep_protocol.h"

#define UUID_LENGTH 16 // Size in bytes of a UUID (RFC 4122)

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
typedef oe_uuid_t teep_uuid_t;
#define TEEP_UUID_SIZE sizeof(oe_uuid_t)
#define TEEP_ASSERT(x) oe_assert(x)
#define _In_
#define _In_z_
#define _In_reads_(x)
#else
#include <assert.h>
#include <stdint.h>
#define TEEP_UUID_SIZE UUID_LENGTH
typedef struct _teep_uuid_t
{
    uint8_t b[TEEP_UUID_SIZE];
} teep_uuid_t;
#define TEEP_ASSERT(x) assert(x)
#endif

#ifdef TEEP_ENABLE_JSON
int TeepHandleJsonMessage(void* sessionHandle, const char* message, unsigned int messageLength);
#endif
teep_error_code_t TeepHandleCborMessage(void* sessionHandle, const char* message, size_t messageLength);
void HexPrintBuffer(const void* buffer, size_t length);

#if defined(TEEP_ENABLE_JSON)
char *DecodeJWS(const json_t *jws, const json_t *jwk);

json_t* CreateNewJwkRS256(void);
json_t* CreateNewJwkR1_5(void);
json_t* CreateNewJwk(const char* alg);
json_t* CopyToJweKey(json_t* jwk1, const char* alg);

const unsigned char* GetDerCertificate(json_t* jwk, size_t *pCertificateSize);
#endif

#ifdef __cplusplus
#include <iostream>
#include <ostream>
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
#endif // __cplusplus

// Prototypes that must be implemented inside the TEE.

#ifdef __cplusplus
extern "C" {
#endif

    // Calls up from broker.

    int TeepInitialize();

    // Calls down to broker.

    teep_error_code_t teep_random(
        _Out_writes_(length) void* buffer,
        size_t length);

#ifdef __cplusplus
}
#endif