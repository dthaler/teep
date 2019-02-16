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
#include "jose/jws.h"
#include "jose/b64.h"
};

void ecall_Initialize()
{
    jose_init();
}

char *DecodeJWS(const json_t *jws, const json_t *jwk)
{
    char *str = NULL;
    size_t len = 0;

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
    }
    else {
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
    if (!json_is_object((json_t*)messageObject)) {
        return 1; /* Error */
    }

    err = OTrPHandleMessage(key, messageObject);

    return err;
}
