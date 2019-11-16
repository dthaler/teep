/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include "TeepAgent_t.h"

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "TrustedApplication.h"
extern "C" {
#include "jansson.h"
#include "joseinit.h"
#include "jose/b64.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
#include "jose/jws.h"
#include "jose/openssl.h"
char* strdup(const char* str);
#include "../TeepCommonTALib/common.h"
};
#include "../jansson/JsonAuto.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "TeepDeviceEcallHandler.h"
#include "OTrPDeviceEcallHandler.h"

// List of TA's requested.
TrustedApplication* g_TARequestList = nullptr;

JsonAuto g_AgentSigningKey;

json_t* GetAgentSigningKey()
{
    if ((json_t*)g_AgentSigningKey == nullptr) {
        g_AgentSigningKey = CreateNewJwkRS256();
    }
    return (json_t*)g_AgentSigningKey;
}

JsonAuto g_AgentEncryptionKey;

json_t* GetAgentEncryptionKey()
{
    if ((json_t*)g_AgentEncryptionKey == nullptr) {
        g_AgentEncryptionKey = CopyToJweKey(GetAgentSigningKey(), "RSA1_5");
    }
    return g_AgentEncryptionKey;
}

const unsigned char* g_AgentDerCertificate = nullptr;
size_t g_AgentDerCertificateSize = 0;

const unsigned char* GetAgentDerCertificate(size_t *pCertLen)
{
    if (g_AgentDerCertificate == nullptr) {
        // Construct a self-signed DER certificate based on the JWK.

        // First get the RSA key.
        json_t* jwk = GetAgentSigningKey();
        g_AgentDerCertificate = GetDerCertificate(jwk, &g_AgentDerCertificateSize);
    }

    *pCertLen = g_AgentDerCertificateSize;
    return g_AgentDerCertificate;
}

int ecall_ProcessError(void* sessionHandle)
{
    // TODO: process transport error
    return 0;
}

int ecall_RequestPolicyCheck(void)
{
    // TODO: request policy check
    return 0;
}

// Returns 0 on success, non-zero on error.
int TeepHandleMessage(void* sessionHandle, const char* key, const json_t* messageObject)
{
    // TODO: handle TEEP message.
    return 1;
}

int ecall_RequestTA(
    const char* taid,
    const char* tamUri)
{
    int err = 0;
    oe_result_t result = OE_OK;
    size_t responseLength = 0;

    // TODO: See whether taid is already installed.
    // For now we skip this step and pretend it's not.
    bool isInstalled = false;

    if (isInstalled) {
        // Already installed, nothing to do.
        // This counts as "pass no data back" in the broker spec.
        return 0;
    }

    // See whether taid is already requested.
    TrustedApplication* ta;
    for (ta = g_TARequestList; ta != nullptr; ta = ta->Next) {
        if (strcmp(ta->ID, taid) == 0) {
            // Already requested, nothing to do.
            // This counts as "pass no data back" in the broker spec.
            return 0;
        }
    }

    // Add taid to the request list.
    ta = new TrustedApplication(taid);
    ta->Next = g_TARequestList;
    g_TARequestList = ta;

    // TODO: we may want to modify the TAM URI here.

    // TODO: see whether we already have a TAM cert we trust.
    // For now we skip this step and say we don't.
    bool haveTrustedTamCert = false;

    if (!haveTrustedTamCert) {
        // Pass back a TAM URI with no buffer.
        result = ocall_Connect(&err, tamUri, OTRP_JSON_MEDIA_TYPE);
        if (result != OE_OK) {
            return result;
        }
        if (err != 0) {
            return err;
        }
    } else {
        // TODO: implement going on to the next message.
        assert(false);
    }

    return err;
}
