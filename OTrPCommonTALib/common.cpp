/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <sgx.h>
#include <sgx_trts.h>
#include <sgx_tprotected_fs.h>
#include <string.h>
#include "../UntrustedTime/enc/UntrustedTimeTALib.h"
#include "OTrPCommonTALib_t.h"
#include "JsonAuto.h"
extern "C" {
#include "../jose/joseinit.h"
#include "../external/jansson/include/jansson.h"
#include "common.h"
#include "jose/jwe.h"
#include "jose/jwk.h"
#include "jose/jws.h"
#include "jose/b64.h"
};

#if 0
void TestJwLibs(void)
{
    const char* message;

    // We do a set of operations that would normally be split between the device and the TAM, to verify correct operation.

    // Verify JWS (signing).
    json_t* jwkTam = CreateNewJwk("RS256");
    message = json_dumps(jwkTam, 0);
    free((char*)message);
    json_t* jws = json_pack("{s:s}", "payload", "foo");
    bool ok = jose_jws_sig(NULL, jws, NULL, jwkTam); // Sign payload.
    message = json_dumps(jws, 0);
    free((char*)message);
    ok = jose_jws_ver(NULL, jws, NULL, jwkTam, false); // Verify the signature.
    json_decref(jws); // Free jws.

    // Convert the RS256 JWK to an RSA1_5 JWK.
    // First, copy the JWK.
    message = json_dumps(jwkTam, 0);
    json_error_t error;
    JsonAuto jwkTam2(json_loads(message, 0, &error), true);
    free((char*)message);
    json_t* rsa15 = json_string("RSA1_5");
    int err;
    err = json_object_set(jwkTam2, "alg", rsa15);
    json_decref(rsa15);
    json_t* key_ops = json_object_get(jwkTam2, "key_ops");
    json_t* wrapKey = json_string("wrapKey");
    json_t* unwrapKey = json_string("unwrapKey");
    err = json_array_clear(key_ops);
    err = json_array_append(key_ops, wrapKey);
    err = json_array_append(key_ops, unwrapKey);
    json_decref(wrapKey);
    json_decref(unwrapKey);

    message = json_dumps(jwkTam2, 0);
    free((char*)message);

    // Verify JWE (encryption).
    json_t* jwe = json_object();
    ok = jose_jwe_enc(NULL, jwe, NULL, jwkTam2, "foo", 4); // Encrypt
    message = json_dumps(jwe, 0);
    free((char*)message);
    size_t ptl = 0;
    char *pt = (char*)jose_jwe_dec(NULL, jwe, NULL, jwkTam2, &ptl); // Decrypt
    json_decref(jwe); // Free jwe
}
#endif

void ecall_Initialize()
{
    jose_init();
}

json_t* CreateNewJwk(const char* alg)
{
    JsonAuto jwk(json_pack("{s:s}", "alg", alg), true);
    if (jwk == NULL) {
        return NULL;
    }

    bool ok = jose_jwk_gen(NULL, jwk);
    if (!ok) {
        return NULL;
    }

    return json_incref(jwk);
}

// Take a JWK created for signing, and create a copy of it usable for encryption.
json_t* CopyToJweKey(json_t* jwk1, const char* alg)
{
    // First, copy the JWK.
    const char* message = json_dumps(jwk1, 0);
    json_error_t error;
    JsonAuto jwk2(json_loads(message, 0, &error), true);
    free((char*)message);
    if (jwk2 == nullptr) {
        return nullptr;
    }
    json_t* algstr = json_string(alg);
    int err = json_object_set(jwk2, "alg", algstr);
    if (err != 0) {
        return nullptr;
    }
    json_decref(algstr);
    json_t* key_ops = json_object_get(jwk2, "key_ops");
    json_t* wrapKey = json_string("wrapKey");
    json_t* unwrapKey = json_string("unwrapKey");
    err = json_array_clear(key_ops);
    if (err != 0) {
        return nullptr;
    }
    err = json_array_append(key_ops, wrapKey);
    if (err != 0) {
        return nullptr;
    }
    err = json_array_append(key_ops, unwrapKey);
    if (err != 0) {
        return nullptr;
    }
    json_decref(wrapKey);
    json_decref(unwrapKey);
    return jwk2.Detach();
}

json_t* CreateNewJwke(void)
{
    return CreateNewJwk("ECDH-ES+A128KW");
}

json_t* CreateNewJwkR1_5(void)
{
    return CreateNewJwk("RSA1_5");
}

json_t* CreateNewJwkRS256(void)
{
    return CreateNewJwk("RS256");
}

char *DecodeJWS(const json_t *jws, const json_t *jwk)
{
    char *str = NULL;
    size_t len = 0;

    // Verify signature, if requested.
    if (jwk != nullptr && !jose_jws_ver(NULL, jws, NULL, jwk, false)) {
        return NULL;
    }

    len = jose_b64_dec(json_object_get(jws, "payload"), NULL, 0);
    str = (char*)malloc(len + 1);
    if (jose_b64_dec(json_object_get(jws, "payload"), str, len) == SIZE_MAX) {
        free(str);
        return NULL;
    }
    str[len] = 0;
    return str;
}

int ecall_ProcessOTrPMessage(
    void* sessionHandle,
    const char* message,
    int messageLength)
{
    int err = 1;
    char *newstr = NULL;

    if (messageLength < 1) {
        return 1; /* error */
    }

    /* Verify string is null-terminated. */
    const char* str = message;
    if (message[messageLength - 1] == 0) {
        str = message;
    } else {
        newstr = (char*)malloc(messageLength + 1);
        if (newstr == NULL) {
            return 1; /* error */
        }
        memcpy(newstr, message, messageLength);
        newstr[messageLength] = 0;
        str = newstr;
    }

    json_error_t error;
    JsonAuto object(json_loads(str, 0, &error), true);

    free(newstr);
    newstr = NULL;

    if ((object == NULL) || !json_is_object((json_t*)object)) {
        return 1; /* Error */
    }
    const char* key = json_object_iter_key(json_object_iter(object));

    ocall_print("Received ");
    ocall_print(key);
    ocall_print("\n");

    JsonAuto messageObject = json_object_get(object, key);

    err = OTrPHandleMessage(sessionHandle, key, messageObject);

    return err;
}
