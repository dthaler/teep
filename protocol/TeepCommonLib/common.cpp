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
    EVP_PKEY* pkey = (EVP_PKEY*)key_pair->key.ptr;

    // Write key pair with private key, for future use by the TAM.
    FILE* fp = fopen(private_file_name, "wb");
    if (fp == nullptr) {
        return TEEP_ERR_PERMANENT_ERROR;
    }
    int succeeded = PEM_write_PrivateKey(fp, (EVP_PKEY*)key_pair->key.ptr,
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
    key_pair->key.ptr = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (key_pair->key.ptr == nullptr) {
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

    key_pair->key.ptr = pkey;
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
    key_pair->key.ptr = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (key_pair->key.ptr == nullptr) {
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
teep_compute_key_id(teep_signature_kind_t signature_kind, _In_ const struct t_cose_key* key_pair, _Out_ UsefulBuf* key_id)
{
#if 1
    // TODO: this is not correct or secure, switch to the other code path once we
    // can get the public key from a t_cose_key key pair.
    *(teep_signature_kind_t*)key_id->ptr = signature_kind;
    key_id->len = sizeof(signature_kind);
    return TEEP_ERR_SUCCESS;
#else
    // Get the public key.
    if (signature_kind == TEEP_SIGNATURE_ES256) {
    }
    else {
    }

    // Compute SHA-256 hash.
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, public_key.key.buffer.ptr, public_key.key.buffer.len);
    SHA256_Final(hash, &sha256);

    *key_id = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(hash);
    return TEEP_ERR_PERMANENT_ERROR;
#endif
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
    UsefulBuf_MAKE_STACK_UB(key_id, SHA256_DIGEST_LENGTH);
    teep_error_code_t result = teep_compute_key_id(signature_kind, key_pair, &key_id);
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }
    t_cose_sign1_set_signing_key(&sign_ctx, *key_pair, UsefulBuf_Const(key_id));

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
    // Initialize for signing.
    struct t_cose_sign_sign_ctx sign_ctx;
    t_cose_sign_sign_init(&sign_ctx, T_COSE_OPT_MESSAGE_TYPE_SIGN);

    struct t_cose_signature_sign_eddsa eddsa_signer;
    struct t_cose_signature_sign_main es256_signer;
    UsefulBuf_MAKE_STACK_UB(eddsa_key_id, SHA256_DIGEST_LENGTH);
    UsefulBuf_MAKE_STACK_UB(es256_key_id, SHA256_DIGEST_LENGTH);
    for (const auto& [kind, key_pair] : key_pairs) {
        int32_t algorithm_id = (kind == TEEP_SIGNATURE_ES256) ? T_COSE_ALGORITHM_ES256 : T_COSE_ALGORITHM_EDDSA;
        if (kind == TEEP_SIGNATURE_ES256) {
            t_cose_signature_sign_main_init(&es256_signer, algorithm_id);
            teep_error_code_t result = teep_compute_key_id(kind, &key_pair, &es256_key_id);
            if (result != TEEP_ERR_SUCCESS) {
                return result;
            }
            t_cose_signature_sign_main_set_signing_key(&es256_signer, key_pair, UsefulBuf_Const(es256_key_id));
            t_cose_sign_add_signer(&sign_ctx, t_cose_signature_sign_from_main(&es256_signer));
        } else {
            t_cose_signature_sign_eddsa_init(&eddsa_signer);
            teep_error_code_t result = teep_compute_key_id(kind, &key_pair, &eddsa_key_id);
            if (result != TEEP_ERR_SUCCESS) {
                return result;
            }
            t_cose_signature_sign_eddsa_set_signing_key(&eddsa_signer, key_pair, UsefulBuf_Const(eddsa_key_id));
            t_cose_sign_add_signer(&sign_ctx, t_cose_signature_sign_from_eddsa(&eddsa_signer));

            // Compute the size of the output and auxiliary buffers.
            struct q_useful_buf null_buff { NULL, SIZE_MAX };
            struct q_useful_buf_c signed_cose;
            enum t_cose_err_t return_value = t_cose_sign_sign(&sign_ctx,
                NULL_Q_USEFUL_BUF_C, // No externally supplied AAD.
                *unsigned_message,
                null_buff,
                &signed_cose);

            // Allocate buffers of the right size.
            if (signed_cose.len > signed_message_buffer.len) {
                return TEEP_ERR_TEMPORARY_ERROR;
            }
            struct q_useful_buf auxiliary_buffer = {};
            auxiliary_buffer.len = t_cose_signature_sign_eddsa_auxiliary_buffer_size(&eddsa_signer);
            if (auxiliary_buffer.len > 0) {
                auxiliary_buffer.ptr = malloc(auxiliary_buffer.len);
                if (auxiliary_buffer.ptr == NULL) {
                    return TEEP_ERR_TEMPORARY_ERROR;
                }
            }

            t_cose_signature_sign_eddsa_set_auxiliary_buffer(&eddsa_signer, auxiliary_buffer);
        }
    }

    // Sign.
    enum t_cose_err_t return_value = t_cose_sign_sign(&sign_ctx,
        NULL_Q_USEFUL_BUF_C, // No externally supplied AAD.
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
    if (return_value != T_COSE_SUCCESS) {
        TeepLogMessage("COSE Sign failed with error %d\n", return_value);
        return TEEP_ERR_PERMANENT_ERROR;
    }

    return TEEP_ERR_SUCCESS;
}

teep_error_code_t
teep_verify_cbor_message_sign1(
    _In_ const struct t_cose_key* key_pair,
    _In_ const UsefulBufC* signed_cose,
    _Out_ UsefulBufC* encoded)
{
    struct t_cose_sign1_verify_ctx verify_ctx;

    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_DECODE_ONLY);
    UsefulBufC payload = {};
    t_cose_err_t return_value = t_cose_sign1_verify(&verify_ctx, *signed_cose, &payload, nullptr);
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
        nullptr);            /* Don't return parameters */
    free(auxiliary_buffer.ptr);
    if (return_value != T_COSE_SUCCESS) {
        TeepLogMessage("Second t_cose_sign1_verify failed with error %d\n", return_value);
        return TEEP_ERR_PERMANENT_ERROR;
    }

    return TEEP_ERR_SUCCESS;
}

// TODO: Define this once https://github.com/laurencelundblade/t_cose/issues/252
// is fixed.
#undef COMPUTE_AUXILIARY_BUFFER_SIZE

teep_error_code_t
teep_verify_cbor_message_sign(
    teep_signature_kind_t signature_kind,
    _In_ const struct t_cose_key* key_pair,
    _In_ const UsefulBufC* signed_cose,
    _Out_ UsefulBufC* encoded)
{
    struct t_cose_sign_verify_ctx verify_ctx;

    UsefulBuf_MAKE_STACK_UB(key_id, SHA256_DIGEST_LENGTH);
    teep_error_code_t result = teep_compute_key_id(signature_kind, key_pair, &key_id);
    if (result != TEEP_ERR_SUCCESS) {
        return result;
    }

    // Initialize verifiers.
#ifndef COMPUTE_AUXILIARY_BUFFER_SIZE
    t_cose_sign_verify_init(&verify_ctx, 0);
#else
    t_cose_sign_verify_init(&verify_ctx, T_COSE_OPT_DECODE_ONLY);
#endif
    struct t_cose_signature_verify_main es256_verifier;
    struct t_cose_signature_verify_eddsa eddsa_verifier;
    if (signature_kind == TEEP_SIGNATURE_ES256) {
        // ES256 verifier.
        t_cose_signature_verify_main_init(&es256_verifier);
        t_cose_signature_verify_main_set_key(&es256_verifier, *key_pair, UsefulBuf_Const(key_id));
        t_cose_sign_add_verifier(&verify_ctx, t_cose_signature_verify_from_main(&es256_verifier));
    } else {
        // EdDSA verifier.
        t_cose_signature_verify_eddsa_init(&eddsa_verifier, 0);
        t_cose_signature_verify_eddsa_set_key(&eddsa_verifier, *key_pair, UsefulBuf_Const(key_id));
        t_cose_sign_add_verifier(&verify_ctx, t_cose_signature_verify_from_eddsa(&eddsa_verifier));
    }

    t_cose_err_t return_value;
    struct q_useful_buf auxiliary_buffer = {};
#ifdef COMPUTE_AUXILIARY_BUFFER_SIZE
    // Compute the auxiliary buffer size needed.
    UsefulBufC payload = {};
    return_value = t_cose_sign_verify(&verify_ctx, *signed_cose, NULL_Q_USEFUL_BUF_C, &payload, nullptr);
    if (return_value != T_COSE_SUCCESS) {
        TeepLogMessage("First t_cose_sign1_verify failed with error %d\n", return_value);
        return TEEP_ERR_PERMANENT_ERROR;
    }
    t_cose_sign_verify_init(&verify_ctx, 0);

    // Allocate an auxiliary buffer of the right size
    auxiliary_buffer.len = t_cose_signature_verify_eddsa_auxiliary_buffer_size(&eddsa_verifier);
#else
    auxiliary_buffer.len = 1024;
#endif
    if (auxiliary_buffer.len > 0) {
        auxiliary_buffer.ptr = malloc(auxiliary_buffer.len);
        if (auxiliary_buffer.ptr == NULL) {
            TeepLogMessage("teep_verify_cbor_message could not allocate %d bytes\n", auxiliary_buffer.len);
            return TEEP_ERR_TEMPORARY_ERROR;
        }
    }
    t_cose_signature_verify_eddsa_set_auxiliary_buffer(&eddsa_verifier, auxiliary_buffer);

    // Do the actual verification.
    return_value = t_cose_sign_verify(&verify_ctx,
        *signed_cose,        /* COSE to verify */
        NULL_Q_USEFUL_BUF_C, /* No AAD */
        encoded,             /* Payload from signed_cose */
        nullptr);            /* Don't return parameters */
    if (return_value != T_COSE_SUCCESS) {
        TeepLogMessage("Second t_cose_sign_verify failed with error %d\n", return_value);
        return TEEP_ERR_PERMANENT_ERROR;
    }

    return TEEP_ERR_SUCCESS;
}

teep_error_code_t
teep_verify_cbor_message(
    teep_signature_kind_t signature_kind,
    _In_ const struct t_cose_key* key_pair,
    _In_ const UsefulBufC* signed_cose,
    _Out_ UsefulBufC* encoded)
{
#if 0
    teep_error_code_t result = teep_verify_cbor_message_sign1(key_pair, signed_cose, encoded);
    if (result == TEEP_ERR_SUCCESS) {
        return TEEP_ERR_SUCCESS;
    }
#endif
    return teep_verify_cbor_message_sign(signature_kind, key_pair, signed_cose, encoded);
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
    EVP_PKEY* pkey = (EVP_PKEY*)key_pair->key.ptr;

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

void TeepLogMessage(_In_z_ const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    vprintf(format, ap);
}

teep_error_code_t GetUuidFromFilename(_In_z_ const char* filename, _Out_ teep_uuid_t* component_id)
{
    teep_error_code_t result = TEEP_ERR_PERMANENT_ERROR;
    char* basename = _strdup(filename);
    if (basename != NULL) {
        size_t len = strlen(basename);
        if ((len > 5) && strcmp(basename + len - 5, ".cbor") == 0) {
            basename[len - 5] = 0;
        }

        int uuid[sizeof(teep_uuid_t)];
        sscanf_s(basename,
            "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            &uuid[0], &uuid[1], &uuid[2], &uuid[3], &uuid[4], &uuid[5], &uuid[6], &uuid[7],
            &uuid[8], &uuid[9], &uuid[10], &uuid[11], &uuid[12], &uuid[13], &uuid[14], &uuid[15]);
        for (size_t i = 0; i < sizeof(teep_uuid_t); i++) {
            component_id->b[i] = uuid[i];
        }
        result = TEEP_ERR_SUCCESS;
    }
    free(basename);
    return result;
}
