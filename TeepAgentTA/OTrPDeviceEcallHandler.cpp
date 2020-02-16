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

#if defined(_ARM_) || defined(_M_ARM) || defined(__arm__) || defined(__thumb__) || defined(__aarch64__)  
# define TEE_NAME "OP-TEE"
#else
# define TEE_NAME "Intel SGX"
#endif

/* Compose a DeviceStateInformation message. */
const char* OTrPComposeDeviceStateInformation(void)
{
    JsonAuto object(json_object(), true);
    if ((json_t*)object == nullptr) {
        return nullptr;
    }

    JsonAuto dsi = object.AddObjectToObject("dsi");
    if ((json_t*)dsi == nullptr) {
        return nullptr;
    }

#ifndef OE_USE_SGX
    /* Add tfwdata. */
    JsonAuto tfwdata = dsi.AddObjectToObject("tfwdata");
    if (tfwdata == nullptr) {
        return nullptr;
    }
    if (tfwdata.AddStringToObject("tbs", "<TFW to be signed data is the tid>") == nullptr) {
        return nullptr;
    }
    if (tfwdata.AddStringToObject("cert", "<BASE64 encoded TFW certificate>") == nullptr) {
        return nullptr;
    }
    if (tfwdata.AddStringToObject("sigalg", "Signing method") == nullptr) {
        return nullptr;
    }
    if (tfwdata.AddStringToObject("sig", "<TFW signed data, BASE64 encoded>") == nullptr) {
        return nullptr;
    }
#endif

    /* Add tee. */
    JsonAuto tee = dsi.AddObjectToObject("tee");
    if (tee == nullptr) {
        return nullptr;
    }
    if (tee.AddStringToObject("name", TEE_NAME) == nullptr) {
        return nullptr;
    }
    if (tee.AddStringToObject("ver", "<TEE version>") == nullptr) {
        return nullptr;
    }
    size_t certLen;
    const unsigned char* cert = GetAgentDerCertificate(&certLen);
    json_t* certJson = jose_b64_enc(cert, certLen);
    if (tee.AddObjectToObject("cert", certJson) == nullptr) {
        return nullptr;
    }
    if (tee.AddObjectToObject("cacert", json_array()) == nullptr) {
        return nullptr;
    }

    // sdlist is optional, so we omit it.

    JsonAuto teeaiklist = tee.AddArrayToObject("teeaiklist");
    if (teeaiklist == nullptr) {
        return nullptr;
    }
    JsonAuto teeaik = teeaiklist.AddObjectToArray();
    if (teeaik == nullptr) {
        return nullptr;
    }
#if 0
    if (teeaik.AddStringToObject("spaik", "<SP AIK public key, BASE64 encoded>") == nullptr) {
        return nullptr;
    }
    if (teeaik.AddStringToObject("spaiktype", "RSA") == nullptr) { // RSA or ECC
        return nullptr;
    }
    if (teeaik.AddStringToObject("spid", "<sp id>") == nullptr) {
        return nullptr;
    }
#endif

    JsonAuto talist = tee.AddArrayToObject("talist");
    if (talist == nullptr) {
        return nullptr;
    }
#if 0
    // TODO: for each TA installed...
    {
        JsonAuto ta = talist.AddObjectToArray();
        if (ta == nullptr) {
            return nullptr;
        }
        if (ta.AddStringToObject("taid", "<TA application identifier>") == nullptr) {
            return nullptr;
        }
        // "taname" field is optional
    }
#endif

    JsonAuto requestedtalist = tee.AddArrayToObject("requestedtalist");
    if (requestedtalist == nullptr) {
        return nullptr;
    }
    for (TrustedApplication* ta = g_TARequestList; ta != nullptr; ta = ta->Next) {
        JsonAuto jta(requestedtalist.AddObjectToArray());
        if (jta == nullptr) {
            return nullptr;
        }
        if (jta.AddStringToObject("taid", ta->ID) == nullptr) {
            return nullptr;
        }
        if (ta->Name[0] != 0) {  // "taname" field is optional
            if (jta.AddStringToObject("taname", ta->Name) == nullptr) {
                return nullptr;
            }
        }
    }

    /* Convert to message buffer. */
    const char* message = json_dumps(object, 0);
    if (message == nullptr) {
        return nullptr;
    }
    return strdup(message);
}

json_t* OTrPAddEdsiToObject(JsonAuto& request, const json_t* jwke)
{
    const char* dsi = OTrPComposeDeviceStateInformation();
    if (dsi == nullptr) {
        return nullptr;
    }
    size_t dsilen = strlen(dsi);

    JsonAuto jwe(json_object(), true);
    bool ok = jose_jwe_enc(
        nullptr,    // Configuration context (optional)
        jwe,     // The JWE object
        nullptr,    // The JWE recipient object(s) or nullptr
        jwke,    // The JWK(s) or JWKSet used for wrapping.
        dsi,     // The plaintext.
        dsilen); // The length of the plaintext.

    free((void*)dsi);
    dsi = nullptr;

    if (!ok) {
        return nullptr;
    }
    return request.AddObjectToObject("edsi", jwe);
}

/* Compose a GetDeviceTEEStateTBSResponse message. */
const char* OTrPComposeGetDeviceTEEStateTBSResponse(
    const json_t* request,    // Request we're responding to.
    const char* statusValue,  // Status string to return.
    const json_t* jwkTam)     // TAM public key to encrypt with.
{
    /* Compose a GetDeviceTEEStateTBSResponse message. */
    JsonAuto object(json_object(), true);
    if (object == nullptr) {
        return nullptr;
    }
    JsonAuto response = object.AddObjectToObject("GetDeviceTEEStateTBSResponse");
    if (response == nullptr) {
        return nullptr;
    }
    if (response.AddStringToObject("ver", "1.0") == nullptr) {
        return nullptr;
    }
    if (response.AddStringToObject("status", statusValue) == nullptr) {
        return nullptr;
    }

    /* Copy rid from request. */
    json_t* rid = json_object_get(request, "rid");
    if (!json_is_string(rid) || (json_string_value(rid) == nullptr)) {
        return nullptr;
    }
    if (response.AddStringToObject("rid", json_string_value(rid)) == nullptr) {
        return nullptr;
    }

    /* Copy tid from request. */
    json_t* tid = json_object_get(request, "tid");
    if (!json_is_string(tid) || (json_string_value(tid) == nullptr)) {
        return nullptr;
    }
    if (response.AddStringToObject("tid", json_string_value(tid)) == nullptr) {
        return nullptr;
    }

    /* Support for signerreq false is optional, so pass true for now. */
    if (response.AddStringToObject("signerreq", "true") == nullptr) {
        return nullptr;
    }

    JsonAuto edsi = response.AddObjectToObject("edsi");
    if (edsi == nullptr) {
        return nullptr;
    }

    if (OTrPAddEdsiToObject(response, jwkTam) == nullptr) {
        return nullptr;
    }

    /* Convert to message buffer. */
    const char* message = json_dumps(object, 0);
    if (message == nullptr) {
        return nullptr;
    }

    return strdup(message);
}

/* Compose a GetDeviceTEEStateResponse message. */
json_t* OTrPComposeGetDeviceTEEStateResponse(
    const json_t* request,    // Request we're responding to.
    const char* statusValue,  // Status string to return.
    const json_t* jwkTam)     // TAM Public key to encrypt with.
{
    /* Get a GetDeviceTEEStateTBSResponse. */
    const char* tbsResponse = OTrPComposeGetDeviceTEEStateTBSResponse(request, statusValue, jwkTam);
    if (tbsResponse == nullptr) {
        return nullptr;
    }
#ifdef _DEBUG
    printf("Sending TBS: %s\n\n", tbsResponse);
#endif
    size_t len = strlen(tbsResponse);
    json_t* b64Response = jose_b64_enc(tbsResponse, len);
    free((void*)tbsResponse);
    if (b64Response == nullptr) {
        return nullptr;
    }

    // Create a signed message.
    JsonAuto jws(json_pack("{s:o}", "payload", b64Response, true));
    if ((json_t*)jws == nullptr) {
        return nullptr;
    }
    json_t* jwkAgent = GetAgentSigningKey();
    bool ok = jose_jws_sig(
        nullptr,   // Configuration context (optional)
        jws,       // The JWE object
        nullptr,
        jwkAgent); // The JWK(s) or JWKSet used for wrapping.
    if (!ok) {
        return nullptr;
    }

    return jws.Detach();
}

// Compose a GetDeviceStateResponse message.
// Returns the message composed, or nullptr on error.
const char* OTrPComposeGetDeviceStateResponse(
    const json_t* request,    // Request we're responding to.
    const char* statusValue,  // Status string to return.
    const json_t* jwkTam)     // TAM public key to encrypt with.
{
    JsonAuto jws(OTrPComposeGetDeviceTEEStateResponse(request, statusValue, jwkTam), true);
    if ((json_t*)jws == nullptr) {
        return nullptr;
    }

    /* Create the final GetDeviceStateResponse message. */
    JsonAuto object(json_object(), true);
    if ((json_t*)object == nullptr) {
        return nullptr;
    }
    JsonAuto dnlist = object.AddArrayToObject("GetDeviceStateResponse");
    if (dnlist == nullptr) {
        return nullptr;
    }
    JsonAuto dn = dnlist.AddObjectToArray();
    if (dn == nullptr) {
        return nullptr;
    }
    if (dn.AddObjectToObject("GetDeviceTEEStateResponse", jws) == nullptr) {
        return nullptr;
    }

    const char* message = json_dumps(object, 0);
    return message;
}

// Returns 0 on success, non-zero on error.
int OTrPHandleGetDeviceStateRequest(void* sessionHandle, const json_t* request)
{
    if (!json_is_object(request)) {
        return 1; /* Error */
    }

    int err = 1;
    oe_result_t result;
    const char* statusValue = "fail";

    /* 1.  Validate JSON message signing.  If it doesn't pass, an error message is returned. */
    char* payload = DecodeJWS(request, nullptr);
    if (!payload) {
        return 1; /* Error */
    }
#ifdef _DEBUG
    printf("Received TBS: %s\n\n", payload);
#endif
    json_error_t error;
    JsonAuto object(json_loads(payload, 0, &error), true);
    if ((json_t*)object == nullptr) {
        return 1;
    }

    /* 2.  Validate that the request TAM certificate is chained to a trusted
     *     CA that the TEE embeds as its trust anchor.
     *
     *     *  Cache the CA OCSP stapling data and certificate revocation
     *        check status for other subsequent requests.
     *
     *     *  A TEE can use its own clock time for the OCSP stapling data
     *        validation.
     */
    json_t* tbsRequest = json_object_get(object, "GetDeviceStateTBSRequest");
    if (tbsRequest == nullptr) {
        return 1;
    }

    // Get the TAM's cert from the request.
    // Each string in the x5c array is a base64 (not base64url) encoded DER certificate.
    json_t* header = json_object_get(request, "header");
    if (header == nullptr) {
        return 1;
    }
    json_t* x5c = json_object_get(header, "x5c");
    if (x5c == nullptr || !json_is_array(x5c) || json_array_size(x5c) == 0) {
        return 1;
    }
    json_t* x5celt = json_array_get(x5c, 0);
    size_t certSize = jose_b64_dec(x5celt, nullptr, 0);
    void* certBuffer = malloc(certSize);
    if (certBuffer == nullptr) {
        return 1;
    }
    if (jose_b64_dec(x5celt, certBuffer, certSize) != certSize) {
        free(certBuffer);
        return 1;
    }

    // TODO: Validate that the request TAM certificate is chained to a trusted
    //       CA that the TEE embeds as its trust anchor.

    // Create a JWK from the server's cert.

    // Read DER buffer into X509 structure per https://stackoverflow.com/questions/6689584/how-to-convert-the-certificate-string-into-x509-structure
    // since the openssl version we currently use does not have d2i_x509() directly.
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, certBuffer, certSize);
    X509* x509 = d2i_X509_bio(bio, nullptr);
    free(certBuffer);
    BIO_free(bio);

    EVP_PKEY *pkey = X509_get_pubkey(x509);
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    JsonAuto jwkTemp(jose_openssl_jwk_from_RSA(nullptr, rsa), true);
    JsonAuto jwkTam(CopyToJweKey(jwkTemp, "RSA1_5"), true);
    EVP_PKEY_free(pkey);

    /* TODO: Cache the CA OCSP stapling data and certificate revocation
    *        check status for other subsequent requests.
    */

    /* 3.  Optionally collect Firmware signed data
     *
     *     *  This is a capability in ARM architecture that allows a TEE to
     *        query Firmware to get FW signed data.It isn't required for
     *        all TEE implementations.When TFW signed data is absent, it
     *        is up to a TAM's policy how it will trust a TEE.
     */
     /* Do nothing since this is optional. */

     /*
      * 4.  Collect SD information for the SD owned by this TAM
      */
      /* TODO */

    statusValue = "pass";

    const char* message = OTrPComposeGetDeviceStateResponse(tbsRequest, statusValue, jwkTam);
    if (message == nullptr) {
        return 1; /* Error */
    }

    printf("Sending GetDeviceStateResponse...\n\n");

    result = ocall_QueueOutboundTeepMessage(&err, sessionHandle, OTRP_JSON_MEDIA_TYPE, message);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

/* Compose the following encrypted content:
       ENCRYPTED {
         "reason":"<failure reason detail>", // optional
         "did": "<the device id hash>",
         "dsi": "<Updated TEE state, including all SD owned by
           this TAM>"
       }
*/
json_t* OTrPComposeInstallTAResponseContent(const char* failureReason, const json_t *jwkTamEncryption)
{
    JsonAuto content(json_object());
    if (failureReason != nullptr) {
        if (content.AddStringToObject("reason", failureReason) == nullptr) {
            return nullptr;
        }
    }

    // TODO: use the SHA256 hash of the binary-encoded device TEE certificate.
    if (content.AddStringToObject("did", "<the device id hash>") == nullptr) {
        return nullptr;
    }

    const char* dsi = OTrPComposeDeviceStateInformation();
    if (dsi == nullptr) {
        return nullptr;
    }
    if (content.AddStringToObject("dsi", dsi) == nullptr) {
        return nullptr;
    }
    free((void*)dsi);

    // Serialize object.
    char* message = json_dumps(content, 0);
    if (message == nullptr) {
        return nullptr;
    }
    int messagelen = strlen(message);

    // Construct a JWE.
    JsonAuto jwe(json_object(), true);
    bool ok = jose_jwe_enc(
        nullptr,          // Configuration context (optional)
        jwe,              // The JWE object
        nullptr,          // The JWE recipient object(s) or nullptr
        jwkTamEncryption, // The JWK(s) or JWKSet used for wrapping.
        message,          // The plaintext.
        messagelen);      // The length of the plaintext.

    free(message);

    return (ok) ? jwe : nullptr;
}

/* Compose an InstallTATBSResponse message. */
const char* OTrPComposeInstallTATBSResponse(
    const json_t* request,    // Request we're responding to.
    const char* statusValue,  // Status string to return.
    const json_t* jwkTam)     // TAM public key to encrypt with.
{
    /* Compose an InstallTATBSResponse message. */
    JsonAuto object(json_object(), true);
    if (object == nullptr) {
        return nullptr;
    }
    JsonAuto response = object.AddObjectToObject("InstallTATBSResponse");
    if (response == nullptr) {
        return nullptr;
    }
    if (response.AddStringToObject("ver", "1.0") == nullptr) {
        return nullptr;
    }
    if (response.AddStringToObject("status", statusValue) == nullptr) {
        return nullptr;
    }

    /* Copy rid from request. */
    json_t* rid = json_object_get(request, "rid");
    if (!json_is_string(rid) || (json_string_value(rid) == nullptr)) {
        return nullptr;
    }
    if (response.AddStringToObject("rid", json_string_value(rid)) == nullptr) {
        return nullptr;
    }

    /* Copy tid from request. */
    json_t* tid = json_object_get(request, "tid");
    if (!json_is_string(tid) || (json_string_value(tid) == nullptr)) {
        return nullptr;
    }
    if (response.AddStringToObject("tid", json_string_value(tid)) == nullptr) {
        return nullptr;
    }

    const char* failureReason = nullptr; // TODO: null means succeeded
    JsonAuto jweContent(OTrPComposeInstallTAResponseContent(failureReason, jwkTam));
    if ((json_t*)jweContent == nullptr) {
        return nullptr;
    }
    if (response.AddObjectToObject("content", jweContent) == nullptr) {
        return nullptr;
    }

    /* Convert to message buffer. */
    const char* message = json_dumps(object, 0);
    if (message == nullptr) {
        return nullptr;
    }

    return strdup(message);
}

/* Compose a InstallTAResponse message. */
const char* OTrPComposeInstallTAResponse(
    const json_t* request,    // Request we're responding to.
    const char* statusValue,  // Status string to return.
    const json_t* jwkTam,     // TAM Public key to encrypt with.
    const json_t* jwkAgent)   // Agent private key to sign with.
{
    /* Get a InstallTATBSResponse. */
    const char* tbsResponse = OTrPComposeInstallTATBSResponse(request, statusValue, jwkTam);
    if (tbsResponse == nullptr) {
        return nullptr;
    }
#ifdef _DEBUG
    printf("Sending TBS: %s\n\n", tbsResponse);
#endif
    size_t len = strlen(tbsResponse);
    json_t* b64Response = jose_b64_enc(tbsResponse, len);
    free((void*)tbsResponse);
    if (b64Response == nullptr) {
        return nullptr;
    }

    // Create a signed message.
    JsonAuto jws(json_pack("{s:o}", "payload", b64Response, true));
    if ((json_t*)jws == nullptr) {
        return nullptr;
    }
    bool ok = jose_jws_sig(
        nullptr,     // Configuration context (optional)
        jws,         // The JWE object
        nullptr,
        jwkAgent);   // The JWK(s) or JWKSet used for wrapping.
    if (!ok) {
        return nullptr;
    }

    /* Create the final InstallTAResponse message. */
    JsonAuto object(json_object(), true);
    if ((json_t*)object == nullptr) {
        return nullptr;
    }
    if (object.AddObjectToObject("InstallTAResponse", jws) == nullptr) {
        return nullptr;
    }

    /* Serialize it to a single string. */
    const char* message = json_dumps(object, 0);
    return message;
}

// Returns 0 on success, non-zero on error.
int OTrPHandleInstallTARequest(void* sessionHandle, const json_t* request)
{
    if (!json_is_object(request)) {
        return 1; /* Error */
    }

    int err = 1;
    oe_result_t result;
    const char* statusValue = "fail";

    /* 1.  Validate JSON message signing.  If it doesn't pass, an error message is returned. */
    char* payload = DecodeJWS(request, nullptr);
    if (!payload) {
        return 1; /* Error */
    }
#ifdef _DEBUG
    printf("Received TBS: %s\n\n", payload);
#endif
    json_error_t error;
    JsonAuto object(json_loads(payload, 0, &error), true);
    if ((json_t*)object == nullptr) {
        return 1;
    }

    /* 2.  Validate that the request TAM certificate is chained to a trusted
     *     CA that the TEE embeds as its trust anchor.
     *
     *     *  Cache the CA OCSP stapling data and certificate revocation
     *        check status for other subsequent requests.
     *
     *     *  A TEE can use its own clock time for the OCSP stapling data
     *        validation.
     */
    json_t* tbsRequest = json_object_get(object, "InstallTATBSRequest");
    if (tbsRequest == nullptr) {
        return 1;
    }

    // Get the TAM's cert from the request.
    // Each string in the x5c array is a base64 (not base64url) encoded DER certificate.
    json_t* header = json_object_get(request, "header");
    if (header == nullptr) {
        return 1;
    }
    json_t* x5c = json_object_get(header, "x5c");
    if (x5c == nullptr || !json_is_array(x5c) || json_array_size(x5c) == 0) {
        return 1;
    }
    json_t* x5celt = json_array_get(x5c, 0);
    size_t certSize = jose_b64_dec(x5celt, nullptr, 0);
    void* certBuffer = malloc(certSize);
    if (certBuffer == nullptr) {
        return 1;
    }
    if (jose_b64_dec(x5celt, certBuffer, certSize) != certSize) {
        free(certBuffer);
        return 1;
    }

    // TODO: Validate that the request TAM certificate is chained to a trusted
    //       CA that the TEE embeds as its trust anchor.

    // Create a JWK from the server's cert.

    // Read DER buffer into X509 structure per https://stackoverflow.com/questions/6689584/how-to-convert-the-certificate-string-into-x509-structure
    // since the openssl version we currently use does not have d2i_x509() directly.
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, certBuffer, certSize);
    X509* x509 = d2i_X509_bio(bio, nullptr);
    free(certBuffer);
    BIO_free(bio);

    EVP_PKEY *pkey = X509_get_pubkey(x509);
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    JsonAuto jwkTemp(jose_openssl_jwk_from_RSA(nullptr, rsa), true);
    JsonAuto jwkTam(CopyToJweKey(jwkTemp, "RSA1_5"), true);
    EVP_PKEY_free(pkey);

    /* TODO: Cache the CA OCSP stapling data and certificate revocation
    *        check status for other subsequent requests.
    */

    /* 3.  Optionally collect Firmware signed data
     *
     *     *  This is a capability in ARM architecture that allows a TEE to
     *        query Firmware to get FW signed data.It isn't required for
     *        all TEE implementations.When TFW signed data is absent, it
     *        is up to a TAM's policy how it will trust a TEE.
     */
     /* Do nothing since this is optional. */

     /*
      * 4.  Collect SD information for the SD owned by this TAM
      */
      /* TODO */

    statusValue = "pass";

    json_t* jwkAgent = GetAgentSigningKey();
    const char* message = OTrPComposeInstallTAResponse(tbsRequest, statusValue, jwkTam, jwkAgent);

    printf("Sending InstallTAResponse...\n\n");

    result = ocall_QueueOutboundTeepMessage(&err, sessionHandle, OTRP_JSON_MEDIA_TYPE, message);
    free((void*)message);
    if (result != OE_OK) {
        return result;
    }
    return err;
}

// Returns 0 on success, non-zero on error.
int OTrPHandleMessage(void* sessionHandle, const char* key, const json_t* messageObject)
{
    if (strcmp(key, "GetDeviceStateRequest") == 0) {
        return OTrPHandleGetDeviceStateRequest(sessionHandle, messageObject);
    }

    if (strcmp(key, "InstallTARequest") == 0) {
        return OTrPHandleInstallTARequest(sessionHandle, messageObject);
    }

    /* Unrecognized message. */
    return 1;
}
