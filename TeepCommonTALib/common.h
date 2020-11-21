/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

#ifdef ENABLE_OTRP
int OTrPHandleJsonMessage(void* sessionHandle, const char* message, unsigned int messageLength);
#endif
#ifdef TEEP_ENABLE_JSON
int TeepHandleJsonMessage(void* sessionHandle, const char* message, unsigned int messageLength);
#endif
int TeepHandleCborMessage(void* sessionHandle, const char* message, unsigned int messageLength);
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

#ifdef _DEBUG
void report_type_error(const char* id, int expected_type, int actual_type);

#define REPORT_TYPE_ERROR(id, expected_type, item) \
    report_type_error(id, expected_type, item.uDataType);
#else
#define REPORT_TYPE_ERROR(id, expected_type, item)
#endif