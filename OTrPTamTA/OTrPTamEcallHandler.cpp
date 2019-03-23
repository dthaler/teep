/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include "OTrPTam_t.h"

#include <stdbool.h>
#include <string.h>
#define FILE void
extern "C" {
#include "jansson.h"
#include "joseinit.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
#include "jose/jws.h"
#include "jose/b64.h"
#include "jose/openssl.h"
#include "../OTrPCommonTALib/common.h"
    char* strdup(const char* str);
};
#include "../jansson/JsonAuto.h"
#include "openssl/x509.h"
#include "openssl/evp.h"

#define UNIQUE_ID_LEN 16

/* Try to constrict a globally unique value. */
json_t* GetNewGloballyUniqueID(void)
{
    /* Create a random 16-byte value. */
    unsigned char value[UNIQUE_ID_LEN];
    oe_result_t result = oe_random(value, UNIQUE_ID_LEN);
    if (result != OE_OK) {
        return nullptr;
    }

    /* Base64-encode it into a string. */
    return jose_b64_enc(value, sizeof(value));
}

/* Construct a unique request ID.  The OTrP spec does not say what
 * the scope of uniqueness needs to be, but we currently try to use
 * globally unique value.
 */
json_t* GetNewRequestID(void)
{
    return GetNewGloballyUniqueID();
}

/* Construct a unique transaction ID.  The OTrP spec does not say what
 * the scope of uniqueness needs to be, but we currently try to use
 * a globally unique value.
 */
json_t* GetNewTransactionID(void)
{
    return GetNewGloballyUniqueID();
}

JsonAuto g_TamSigningKey;

json_t* GetTamSigningKey()
{
    if ((json_t*)g_TamSigningKey == nullptr) {
        g_TamSigningKey = CreateNewJwkRS256();
    }
    return (json_t*)g_TamSigningKey;
}

JsonAuto g_TamEncryptionKey;

json_t* GetTamEncryptionKey()
{
    if ((json_t*)g_TamEncryptionKey == nullptr) {
        g_TamEncryptionKey = CopyToJweKey(GetTamSigningKey(), "RSA1_5");
    }
    return g_TamEncryptionKey;
}

unsigned char* g_TamDerCertificate = nullptr;
size_t g_TamDerCertificateSize = 0;

void* GetTamDerCertificate(size_t *pCertLen)
{
    if (g_TamDerCertificate == nullptr) {
        // Construct a self-signed DER certificate based on the JWK.

        // First get the RSA key.
        json_t* jwk = GetTamEncryptionKey();
        RSA *rsa = jose_openssl_jwk_to_RSA(nullptr, jwk);

        // Now that we have the RSA key we can do the rest by following the steps at
        // https://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl

        // Get the private key.
        EVP_PKEY* pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsa);

        // Create a certificate.
        X509* x509 = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0); // Current time
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year from now
        X509_set_pubkey(x509, pkey);

        // We set the name of the issuer to the name of the subject, for a self-signed cert.
        X509_NAME* name = X509_get_subject_name(x509);

        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"MyCompany Inc.", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
        X509_set_issuer_name(x509, name);

        // Now sign the certificate with the private key using SHA1.
        X509_sign(x509, pkey, EVP_sha1());

        // We now have a self-signed certificate and need to get the DER form of it.
        g_TamDerCertificateSize = i2d_X509(x509, nullptr);
        g_TamDerCertificate = (unsigned char*)malloc(g_TamDerCertificateSize);
        unsigned char* out = g_TamDerCertificate;
        g_TamDerCertificateSize = i2d_X509(x509, &out);

        X509_free(x509);
        EVP_PKEY_free(pkey); // This also frees rsa.
    }

    *pCertLen = g_TamDerCertificateSize;
    return g_TamDerCertificate;
}

/* Compose a GetDeviceStateTBSRequest message. */
const char* ComposeGetDeviceStateTBSRequest(void)
{
    JsonAuto object(json_object(), true);
    if (object == nullptr) {
        return nullptr;
    }
    JsonAuto request = object.AddObjectToObject("GetDeviceStateTBSRequest");
    if (request == nullptr) {
        return nullptr;
    }
    if (request.AddStringToObject("ver", "1.0") == nullptr) {
        return nullptr;
    }
    if (request.AddObjectToObject("rid", GetNewRequestID()) == nullptr) {
        return nullptr;
    }
    if (request.AddObjectToObject("tid", GetNewTransactionID()) == nullptr) {
        return nullptr;
    }
    JsonAuto ocspdat = request.AddArrayToObject("ocspdat");
    if (ocspdat == nullptr) {
        return nullptr;
    }
    /* TODO: Fill in list of OCSP stapling data. */

    /* supportedsigalgs is optional, so omit for now. */

    /* Convert to message buffer. */
    const char* message = json_dumps(object, 0);
    if (message == nullptr) {
        return nullptr;
    }
    return strdup(message);
}

const char* ComposeGetDeviceStateRequest(void)
{
    json_t* jwk = GetTamSigningKey();

    /* Compose a raw GetDeviceState request to be signed. */
    const char* tbsRequest = ComposeGetDeviceStateTBSRequest();
    if (tbsRequest == nullptr) {
        return nullptr;
    }
#ifdef _DEBUG
    ocall_print("Sending TBS: ");
    ocall_print(tbsRequest);
#endif

    /* Base64 encode it. */
    size_t len = strlen(tbsRequest);
    json_t* b64Request = jose_b64_enc(tbsRequest, len);
    free((void*)tbsRequest);
    if (b64Request == nullptr) {
        return nullptr;
    }

    /* Create the signed message. */
    JsonAuto jws(json_pack("{s:o}", "payload", b64Request), true);
    if ((json_t*)jws == nullptr) {
        return nullptr;
    }

    JsonAuto sig(json_object(), true);
    JsonAuto header = sig.AddObjectToObject("header");
    if ((json_t*)header == nullptr) {
        return nullptr;
    }
    JsonAuto x5c(json_array(), true);
    if (json_object_set_new(header, "x5c", x5c) < 0) {
        return nullptr;
    }

    // Get TAM DER cert.
    size_t certLen;
    void* cert = GetTamDerCertificate(&certLen);
    json_t* certJson = jose_b64_enc(cert, certLen);
    if (json_array_append(x5c, certJson) < 0) {
        return nullptr;
    }

    bool ok = jose_jws_sig(
        nullptr,    // Configuration context (optional)
        jws,     // The JWE object
        sig,     // The JWE recipient object(s) or nullptr
        jwk);   // The JWK(s) or JWKSet used for wrapping.
    if (!ok) {
        return nullptr;
    }

    /* Create the final GetDeviceStateRequest message. */
    JsonAuto object(json_object(), true);
    if ((json_t*)object == nullptr) {
        return nullptr;
    }
    if (object.AddObjectToObject("GetDeviceStateRequest", jws) == nullptr) {
        return nullptr;
    }

    /* Serialize it to a single string. */
    const char* message = json_dumps(object, 0);
    return message;
}

/* Handle a new incoming connection from a device. */
int ecall_ProcessOTrPConnect(void* sessionHandle)
{
    ocall_print("Received client connection\n");

    const char* message = ComposeGetDeviceStateRequest();
    if (message == nullptr) {
        return 1; /* Error */
    }

    ocall_print("Sending GetDeviceStateRequest...\n");

    int err = 0;
    oe_result_t result = ocall_SendOTrPMessage(&err, sessionHandle, message);
    free((void*)message);
    if (result != OE_OK) {
        return result;
    }

    return err;
}

/* Handle a GetDeviceTEEStateResponse from an OTrP Agent. */
int OTrPHandleGetDeviceTEEStateResponse(void* sessionHandle, const json_t* messageObject)
{
    if (!json_is_object(messageObject)) {
        return 1; /* Error */
    }

    /* Get the JWS signed object. */
    json_t* jws = json_object_get(messageObject, "GetDeviceTEEStateResponse");
    if (jws == nullptr) {
        return 1; /* Error */
    }
#ifdef _DEBUG
    const char* message = json_dumps(jws, 0);
    free((char*)message);
#endif

    /* Parse the JSON "payload" property and decrypt the JSON element
     * "edsi".  The decrypted message contains the TEE signer
     * certificate.
     */

    char* payload = DecodeJWS(jws, nullptr);
    if (payload == nullptr) {
        return 1; /* Error */
    }

    JsonAuto object(json_loads(payload, 0, nullptr));
    free(payload);
    if ((json_t*)object == nullptr) {
        return 1; /* Error */
    }

    json_t* tbs = json_object_get(object, "GetDeviceTEEStateTBSResponse");
    if (tbs == nullptr || !json_is_object(tbs)) {
        return 1; /* Error */
    }

    json_t* edsi = json_object_get(tbs, "edsi");
    if (edsi == nullptr || !json_is_object(edsi)) {
        return 1; /* Error */
    }

    /* Decrypt the edsi. */
    json_t* jwkEncryption = GetTamEncryptionKey();
    size_t len = 0;
    char* dsistr = (char*)jose_jwe_dec(nullptr, edsi, nullptr, jwkEncryption, &len);
    if (dsistr == nullptr) {
        return 1; /* Error */
    }
    json_error_t error;
    JsonAuto dsi(json_loads(dsistr, 0, &error), true);
    free(dsistr);
    if ((json_t*)dsi == nullptr) {
        return 1; /* Error */
    }

    /* Verify the signature. */
    json_t* jwkSigning = GetTamSigningKey();
    // TODO

    return 0; /* no error */
}

/* Handle a GetDeviceStateResponse from an OTrP Agent. */
int OTrPHandleGetDeviceStateResponse(void* sessionHandle, const json_t* messageObject)
{
    if (!json_is_array(messageObject)) {
        return 1; /* Error */
    }

    // Parse to get list of GetDeviceTEEStateResponse JSON objects.
    size_t index;
    json_t* value;
    json_array_foreach(messageObject, index, value) {
        int err = OTrPHandleGetDeviceTEEStateResponse(sessionHandle, value);
        if (err != 0) {
            return err;
        }
    }

    return 0; /* no error */
}

/* Handle an incoming message from an OTrP Agent. */
/* Returns 0 on success, or non-zero if error. */
int OTrPHandleMessage(void* sessionHandle, const char* key, const json_t* messageObject)
{
    if (strcmp(key, "GetDeviceStateResponse") == 0) {
        return OTrPHandleGetDeviceStateResponse(sessionHandle, messageObject);
    }

    /* Unrecognized message. */
    return 1;
}
