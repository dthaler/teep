// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once

// This file has defines that are in common between
// the TAM and the TEEP Agent.

#define TEEP_USE_COSE 1 // If undefined, messages will be sent in the clear for debugging.

#define UUID_LENGTH 16 // Size in bytes of a UUID (RFC 4122)

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
typedef oe_uuid_t teep_uuid_t;
#define TEEP_UUID_SIZE sizeof(oe_uuid_t)
#define TEEP_ASSERT(x) oe_assert(x)
#define _In_
#define _In_z_
#define _In_reads_(x)
#define _Out_
#define _Out_writes_(x)
#define _Out_writes_opt_z_(x)
#define _Ret_writes_bytes_(x)
#define _Ret_writes_bytes_maybenull_(x)
#define _Return_type_success_(x)
#define strcpy_s(dest, dest_sz, src) strcpy(dest, src)
#define sprintf_s(dest, sz, ...) sprintf(dest, __VA_ARGS__)
#define _strdup strdup
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
#define TEEP_UNUSED(x) (void)(x)

#include "teep_protocol.h"
#include "qcbor/UsefulBuf.h"

void HexPrintBuffer(_In_opt_z_ const char* label, const void* buffer, size_t length);

void TeepLogMessage(_In_ const char* format, ...);

typedef enum {
    TEEP_SIGNATURE_NONE,  // For debugging only.
    TEEP_SIGNATURE_ES256, // Sign1 with ES256
    TEEP_SIGNATURE_EDDSA, // Sign1 with EdDSA
    TEEP_SIGNATURE_BOTH,  // Sign with ES256 and EdDSA
} teep_signature_kind_t;

teep_error_code_t teep_load_signing_key_pair(
    _Out_ struct t_cose_key* key_pair,
    _In_z_ const char* private_file_name,
    _In_z_ const char* public_file_name,
    teep_signature_kind_t signature_kind);

teep_error_code_t teep_get_verifying_key_pair(
    _Out_ struct t_cose_key* key_pair,
    _In_z_ const char* public_file_name);

teep_error_code_t
teep_sign1_cbor_message(
    _In_ const struct t_cose_key* key_pair,
    _In_ const UsefulBufC* unsigned_message,
    _In_ UsefulBuf signed_message_buffer,
    teep_signature_kind_t signature_kind,
    _Out_ UsefulBufC* signed_message);

#ifdef __cplusplus
#include <map>
teep_error_code_t
teep_sign_cbor_message(
    _In_ std::map<teep_signature_kind_t, struct t_cose_key>& key_pairs,
    _In_ const UsefulBufC* unsigned_message,
    _In_ UsefulBuf signed_message_buffer,
    teep_signature_kind_t signature_kind,
    _Out_ UsefulBufC* signed_message);
#endif

teep_error_code_t
teep_verify_cbor_message(
    _In_ const struct t_cose_key* key_pair,
    _In_ const UsefulBufC* signed_cose,
    _Out_ UsefulBufC* encoded);

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

    teep_error_code_t TeepInitialize(_In_z_ const char* signing_private_key_pair_filename, _In_z_ const char* signing_public_key_filename,
        teep_signature_kind_t signature_kind);

    // Calls down to broker.

    teep_error_code_t teep_random(
        _Out_writes_(length) void* buffer,
        size_t length);

#ifdef __cplusplus
}
#endif
