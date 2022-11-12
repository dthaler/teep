// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
//
// This file contains trusted code in common between the TAM and TEEP Agent.
#include <stdio.h>
#include <string.h>
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "common.h"
extern "C" {
#ifdef TEEP_USE_TEE
#define _countof(x) OE_COUNTOF(x)
#define sprintf_s(dest, len, ...) sprintf(dest, __VA_ARGS__)
#endif
#include "teep_protocol.h"
#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
};

static const char* cbor_type_name[] = {
    nullptr, nullptr , "int64", "uint64", "array", "map", "bstr", "tstr"
};

static const char* get_cbor_type_name(unsigned int type)
{
    if ((type >= _countof(cbor_type_name)) || cbor_type_name[type] == nullptr) {
        static char buffer[80];
        sprintf_s(buffer, sizeof(buffer), "? (%d)", type);
        return buffer;
    }
    return cbor_type_name[type];
}

void report_type_error(std::ostream& s, const char* id, int expected_type, int actual_type)
{
    s << "Invalid " << id << " type " << get_cbor_type_name(actual_type) << ", expected " << get_cbor_type_name(expected_type) << std::endl;
}

static teep_error_code_t _save_signing_key_pair(
    _In_ const struct t_cose_key* key_pair,
    _In_z_ const char* private_file_name,
    _In_z_ const char* public_file_name)
{
    EVP_PKEY* pkey = (EVP_PKEY*)key_pair->k.key_ptr;

    // Write key pair with private key, for future use by the TAM.
    FILE* fp = fopen(private_file_name, "wb");
    if (fp == nullptr) {
        return TEEP_ERR_PERMANENT_ERROR;
    }
    int succeeded = PEM_write_PrivateKey(fp, (EVP_PKEY*)key_pair->k.key_ptr,
        NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    if (!succeeded) {
        return TEEP_ERR_PERMANENT_ERROR;
    }

    // Write public key for use by TEEP Agents.
    fp = fopen(public_file_name, "wb");
    if (fp == nullptr) {
        return TEEP_ERR_PERMANENT_ERROR;
    }
    succeeded = PEM_write_PUBKEY(fp, pkey);
    fclose(fp);
    if (!succeeded) {
        return TEEP_ERR_PERMANENT_ERROR;
    }

    return TEEP_ERR_SUCCESS;
}

static teep_error_code_t _load_signing_key_pair(
    _Out_ struct t_cose_key* key_pair,
    _In_z_ const char* file_name)
{
    FILE* fp = fopen(file_name, "rb");
    if (fp == nullptr) {
        return TEEP_ERR_PERMANENT_ERROR;
    }
    key_pair->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    key_pair->k.key_ptr = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (key_pair->k.key_ptr == nullptr) {
        return TEEP_ERR_PERMANENT_ERROR;
    }

    return TEEP_ERR_SUCCESS;
}

/**
 * \brief Make a key pair in OpenSSL library form.
 *
 * \param[in] cose_algorithm_id  The algorithm to sign with, for example
 *                               \ref T_COSE_ALGORITHM_ES256.
 * \param[out] key_pair          The key pair. This must be freed.
 *
 * The key made here is fixed and just useful for testing.
 */
static enum t_cose_err_t _make_ossl_key_pair(
    int32_t cose_algorithm_id,
    _Out_ struct t_cose_key* key_pair)
{
    enum t_cose_err_t return_value;
    int ossl_result;
    int ossl_key_type;
    int ossl_curve_nid;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx;

    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        ossl_key_type = EVP_PKEY_EC;
        ossl_curve_nid = NID_X9_62_prime256v1;
        break;

    case T_COSE_ALGORITHM_ES384:
        ossl_key_type = EVP_PKEY_EC;
        ossl_curve_nid = NID_secp384r1;
        break;

    case T_COSE_ALGORITHM_ES512:
        ossl_key_type = EVP_PKEY_EC;
        ossl_curve_nid = NID_secp521r1;
        break;

    case T_COSE_ALGORITHM_EDDSA:
        ossl_key_type = EVP_PKEY_ED25519;
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    ctx = EVP_PKEY_CTX_new_id(ossl_key_type, NULL);
    if (ctx == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        return_value = T_COSE_ERR_FAIL;
        goto Done;
    }

    if (ossl_key_type == EVP_PKEY_EC) {
        ossl_result = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, ossl_curve_nid);
        if (ossl_result != 1) {
            return_value = T_COSE_ERR_FAIL;
            goto Done;
        }
    }

    pkey = EVP_PKEY_new();

    ossl_result = EVP_PKEY_keygen(ctx, &pkey);

    if (ossl_result != 1) {
        return_value = T_COSE_ERR_FAIL;
        goto Done;
    }

    key_pair->k.key_ptr = pkey;
    key_pair->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}

static int get_cose_algorithm(teep_signature_kind_t signature_kind)
{
    switch (signature_kind) {
    case TEEP_SIGNATURE_ES256: return T_COSE_ALGORITHM_ES256;
    case TEEP_SIGNATURE_EDDSA: return T_COSE_ALGORITHM_EDDSA;
    default: return TEEP_ERR_PERMANENT_ERROR;
    }
}

teep_error_code_t teep_load_signing_key_pair(
    _Out_ struct t_cose_key* key_pair,
    _In_z_ const char* private_file_name,
    _In_z_ const char* public_file_name,
    teep_signature_kind_t signature_kind)
{
    int cose_algorithm = get_cose_algorithm(signature_kind);

    if (_load_signing_key_pair(key_pair, private_file_name) == TEEP_ERR_PERMANENT_ERROR) {
        TeepLogMessage("Creating new key in %s\n", public_file_name);
        enum t_cose_err_t return_value = _make_ossl_key_pair(cose_algorithm, key_pair);
        if (return_value != T_COSE_SUCCESS) {
            return TEEP_ERR_TEMPORARY_ERROR;
        }

        teep_error_code_t result = _save_signing_key_pair(key_pair, private_file_name, public_file_name);
        if (result != TEEP_ERR_SUCCESS) {
            return result;
        }
    }

    return TEEP_ERR_SUCCESS;
}

teep_error_code_t teep_get_verifying_key_pair(
    _Out_ struct t_cose_key* key_pair,
    _In_z_ const char* public_file_name)
{
    FILE* fp = fopen(public_file_name, "rb");
    if (fp == nullptr) {
        return TEEP_ERR_PERMANENT_ERROR;
    }
    key_pair->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    key_pair->k.key_ptr = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (key_pair->k.key_ptr == nullptr) {
        return TEEP_ERR_PERMANENT_ERROR;
    }
    return TEEP_ERR_SUCCESS;
}

teep_error_code_t TeepInitialize(_In_z_ const char* signing_private_key_pair_filename, _In_z_ const char* signing_public_key_filename, teep_signature_kind_t signature_kind)
{
    struct t_cose_key key_pair;
    return teep_load_signing_key_pair(&key_pair, signing_private_key_pair_filename, signing_public_key_filename, signature_kind);
}

teep_error_code_t
teep_sign1_cbor_message(
    _In_ const struct t_cose_key* key_pair,
    _In_ const UsefulBufC* unsigned_message,
    _In_ UsefulBuf signed_message_buffer,
    teep_signature_kind_t signature_kind,
    _Out_ UsefulBufC* signed_message)
{
    // Initialize for signing.
    struct t_cose_sign1_sign_ctx sign_ctx;
    t_cose_sign1_sign_init(&sign_ctx, 0, get_cose_algorithm(signature_kind));
    t_cose_sign1_set_signing_key(&sign_ctx, *key_pair, NULL_Q_USEFUL_BUF_C);

    // Compute the size of the output and auxiliary buffers.
    struct q_useful_buf null_buff { NULL, SIZE_MAX };
    struct q_useful_buf_c signed_cose;
    enum t_cose_err_t return_value = t_cose_sign1_sign(&sign_ctx,
        *unsigned_message,
        null_buff,
        &signed_cose);

    // Allocate buffers of the right size.
    if (signed_cose.len > signed_message_buffer.len) {
        return TEEP_ERR_TEMPORARY_ERROR;
    }
    struct q_useful_buf auxiliary_buffer = {};
    auxiliary_buffer.len = t_cose_sign1_sign_auxiliary_buffer_size(&sign_ctx);
    if (auxiliary_buffer.len > 0) {
        auxiliary_buffer.ptr = malloc(auxiliary_buffer.len);
        if (auxiliary_buffer.ptr == NULL) {
            return TEEP_ERR_TEMPORARY_ERROR;
        }
    }

    // Sign.
    t_cose_sign1_sign_set_auxiliary_buffer(&sign_ctx, auxiliary_buffer);
    return_value = t_cose_sign1_sign(
        &sign_ctx,
        *unsigned_message,
        /* Non-const pointer and length of the
         * buffer where the completed output is
         * written to. The length here is that
         * of the whole buffer.
         */
        signed_message_buffer,
        /* Const pointer and actual length of
         * the completed, signed and encoded
         * COSE_Sign1 message. This points
         * into the output buffer and has the
         * lifetime of the output buffer.
         */
        signed_message);
    free(auxiliary_buffer.ptr);
    if (return_value != T_COSE_SUCCESS) {
        TeepLogMessage("COSE Sign1 failed with error %d\n", return_value);
        return TEEP_ERR_PERMANENT_ERROR;
    }

    return TEEP_ERR_SUCCESS;
}

teep_error_code_t
teep_sign_cbor_message(
    _In_ std::map<teep_signature_kind_t, struct t_cose_key>& key_pairs,
    _In_ const UsefulBufC* unsigned_message,
    _In_ UsefulBuf signed_message_buffer,
    teep_signature_kind_t signature_kind,
    _Out_ UsefulBufC* signed_message)
{
    // TODO(#104): t_cose 2.0 should support Sign.
    // Switch to it once it's ready and supports EdDSA.
    // In the meantime, we just use Sign1.

    return teep_sign1_cbor_message(&key_pairs[TEEP_SIGNATURE_ES256],
        unsigned_message,
        signed_message_buffer,
        TEEP_SIGNATURE_ES256,
        signed_message);
}

teep_error_code_t
teep_verify_cbor_message(
    _In_ const struct t_cose_key* key_pair,
    _In_ const UsefulBufC* signed_cose,
    _Out_ UsefulBufC* encoded)
{
    struct t_cose_sign1_verify_ctx verify_ctx;

    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_DECODE_ONLY);
    int return_value = t_cose_sign1_verify(&verify_ctx, *signed_cose, NULL, NULL);
    if (return_value != T_COSE_SUCCESS) {
        TeepLogMessage("First t_cose_sign1_verify failed with error %d\n", return_value);
        return TEEP_ERR_PERMANENT_ERROR;
    }

    // Allocate an auxiliary buffer of the right size.
    struct q_useful_buf auxiliary_buffer = {};
    auxiliary_buffer.len = t_cose_sign1_verify_auxiliary_buffer_size(&verify_ctx);
    if (auxiliary_buffer.len > 0) {
        auxiliary_buffer.ptr = malloc(auxiliary_buffer.len);
        if (auxiliary_buffer.ptr == NULL) {
            TeepLogMessage("teep_verify_cbor_message could not allocate %d bytes\n", auxiliary_buffer.len);
            return TEEP_ERR_TEMPORARY_ERROR;
        }
    }

    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, *key_pair);
    t_cose_sign1_verify_set_auxiliary_buffer(&verify_ctx, auxiliary_buffer);

    return_value = t_cose_sign1_verify(&verify_ctx,
        *signed_cose,        /* COSE to verify */
        encoded,             /* Payload from signed_cose */
        NULL);               /* Don't return parameters */
    free(auxiliary_buffer.ptr);
    if (return_value != T_COSE_SUCCESS) {
        TeepLogMessage("Second t_cose_sign1_verify failed with error %d\n", return_value);
        return TEEP_ERR_PERMANENT_ERROR;
    }

    return TEEP_ERR_SUCCESS;
}

#ifdef TEEP_USE_CERTIFICATES // Currently unused.
_Ret_writes_bytes_maybenull_(*pCertificateSize)
const unsigned char* GetDerCertificate(
    _In_ const struct t_cose_key* key_pair,
    _Out_ size_t *pCertificateSize)
{
    // Follow the steps at
    // https://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl

    // Get the private key.
    EVP_PKEY* pkey = (EVP_PKEY*)key_pair->k.key_ptr;

    // Create a certificate.
    X509* x509 = X509_new();
    if (x509 == nullptr) {
        *pCertificateSize = 0;
        return nullptr;
    }
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
    *pCertificateSize = i2d_X509(x509, nullptr);
    unsigned char* cert = (unsigned char*)malloc(*pCertificateSize);
    unsigned char* out = cert;
    i2d_X509(x509, &out);

    X509_free(x509);

    return cert;
}
#endif

void HexPrintBuffer(_In_opt_z_ const char* label, const void* buffer, size_t length)
{
    const unsigned char* charbuffer = (const unsigned char*)buffer;

    if (label) {
        printf(label);
    }
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", charbuffer[i]);
    }
    printf("\n");
}

#ifndef TEEP_USE_TEE
#include <random>
teep_error_code_t teep_random(
    _Out_writes_(length) void* buffer,
    size_t length)
{
    std::random_device rd;  // non-deterministic generator
    std::mt19937 gen(rd()); // to seed mersenne twister.
                            // replace the call to rd() with a
                            // constant value to get repeatable
                            // results.
    for (size_t i = 0; i < length; i++) {
        ((uint8_t*)buffer)[i] = gen() % 256;
    }
    return TEEP_ERR_SUCCESS;
}
#endif

void TeepLogMessage(_In_ const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    vprintf(format, ap);
}
