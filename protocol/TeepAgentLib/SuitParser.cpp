// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#ifdef TEEP_USE_TEE
#include <openenclave/enclave.h>
#endif
#include <stdlib.h>
#include "common.h"
extern "C" {
#include "suit_manifest.h"
};
#include "qcbor/qcbor_decode.h"
#include "SuitParser.h"

// Construct a filename from a SUIT_Digest.
static teep_error_code_t GetFilenameFromSuitDigest(_Out_ filesystem::path& filename, UsefulBufC encoded)
{
    teep_error_code_t errorCode = TEEP_ERR_PERMANENT_ERROR;
    QCBORDecodeContext context;
    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORItem item;
    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_ARRAY && item.val.uCount > 0) {
        QCBORDecode_GetNext(&context, &item);
        if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
            // Base16 encode item.val.string.
            TeepAgentMakeManifestFilename(filename, (char*)item.val.string.ptr, item.val.string.len);
            errorCode = TEEP_ERR_SUCCESS;
        }
    }
    QCBORDecode_Finish(&context);
    return errorCode;
}

// Construct a filename from a SUIT_Authentication.
static teep_error_code_t GetFilenameFromSuitAuthentication(_Out_ filesystem::path& filename, UsefulBufC encoded)
{
    teep_error_code_t errorCode = TEEP_ERR_PERMANENT_ERROR;
    QCBORDecodeContext context;
    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORItem item;
    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount > 0) {
        QCBORDecode_GetNext(&context, &item);
        if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
            errorCode = GetFilenameFromSuitDigest(filename, item.val.string);
        }
    }
    QCBORDecode_Finish(&context);
    return errorCode;
}

// Construct a filename from a SUIT_Component_Identifier.
static teep_error_code_t GetFilenameFromSuitComponentIdentifier(_Out_ filesystem::path& filename, QCBORDecodeContext* context, QCBORItem* item, ostream& errorMessage)
{
    if (item->uDataType != QCBOR_TYPE_ARRAY) {
        REPORT_TYPE_ERROR(errorMessage, "suit-manifest-component-id", QCBOR_TYPE_ARRAY, *item);
        return TEEP_ERR_MANIFEST_PROCESSING_FAILED;
    }

    // Get array size.
    uint16_t componentIdEntryCount = item->val.uCount;
    if (componentIdEntryCount < 1) {
        return TEEP_ERR_MANIFEST_PROCESSING_FAILED;
    }

    for (uint16_t i = 0; i < componentIdEntryCount; i++) {
        // Read bstr from component id array.
        QCBORDecode_GetNext(context, item);
        if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
            REPORT_TYPE_ERROR(errorMessage, "component-id", QCBOR_TYPE_BYTE_STRING, *item);
            return TEEP_ERR_MANIFEST_PROCESSING_FAILED;
        }
    }

    // Return the last bstr as the suffix.
    TeepAgentMakeManifestFilename(filename, (const char*)item->val.string.ptr, item->val.string.len);
    return TEEP_ERR_SUCCESS;
}

// Construct a filename from a SUIT_Common.
static teep_error_code_t GetFilenameFromSuitCommon(_Out_ filesystem::path& filename, UsefulBufC encoded, std::ostream& errorMessage)
{
    teep_error_code_t errorCode = TEEP_ERR_PERMANENT_ERROR;
    QCBORDecodeContext context;
    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORItem item;
    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType == QCBOR_TYPE_MAP) {
        size_t entryCount = item.val.uCount;
        for (size_t entryIndex = 0; entryIndex < entryCount; entryIndex++) {
            QCBORDecode_GetNext(&context, &item);
            suit_common_label_t label = (suit_common_label_t)item.label.int64;
            if (label != SUIT_COMMON_LABEL_COMPONENTS) {
                continue;
            }
            if (item.uDataType != QCBOR_TYPE_ARRAY) {
                break;
            }
            if (item.val.uCount < 1) {
                break;
            }

            // Get first array entry.
            QCBORDecode_GetNext(&context, &item);
            errorCode = GetFilenameFromSuitComponentIdentifier(filename, &context, &item, errorMessage);
            break;
        }
    }
    QCBORDecode_Finish(&context);
    return errorCode;
}

// Construct a filename from a SUIT_Manifest.
static teep_error_code_t GetFilenameFromSuitManifest(_Out_ filesystem::path& filename, UsefulBufC encoded, std::ostream& errorMessage)
{
    teep_error_code_t errorCode = TEEP_ERR_PERMANENT_ERROR;
    QCBORDecodeContext context;
    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORItem item;
    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType == QCBOR_TYPE_MAP) {
        size_t entryCount = item.val.uCount;
        for (size_t entryIndex = 0; entryIndex < entryCount; entryIndex++) {
            QCBORDecode_GetNext(&context, &item);
            suit_envelope_label_t label = (suit_envelope_label_t)item.label.int64;
            if (label == SUIT_MANIFEST_LABEL_COMMON) {
                if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                    break;
                }
                errorCode = GetFilenameFromSuitCommon(filename, item.val.string, errorMessage);

                // Keep going in case we actually find a manifest component ID.
                continue;
            }
            if (label == SUIT_MANIFEST_LABEL_COMPONENT_ID) {
                errorCode = GetFilenameFromSuitComponentIdentifier(filename, &context, &item, errorMessage);
                break;
            }
        }
    }
    QCBORDecode_Finish(&context);
    return errorCode;
}

// Construct a filename from a SUIT_Envelope.
static teep_error_code_t GetFilenameFromSuitEnvelope(_Out_ filesystem::path& filename, UsefulBufC encoded, std::ostream& errorMessage)
{
    teep_error_code_t errorCode = TEEP_ERR_PERMANENT_ERROR;
    QCBORDecodeContext context;
    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORItem item;
    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType == QCBOR_TYPE_MAP) {
        size_t entryCount = item.val.uCount;
        for (size_t entryIndex = 0; entryIndex < entryCount; entryIndex++) {
            QCBORDecode_GetNext(&context, &item);
            suit_envelope_label_t label = (suit_envelope_label_t)item.label.int64;
            if (label == SUIT_ENVELOPE_LABEL_AUTHENTICATION_WRAPPER) {
                if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                    break;
                }
                errorCode = GetFilenameFromSuitAuthentication(filename, item.val.string);
                if (errorCode == TEEP_ERR_SUCCESS) {
                    break;
                }
                continue;
            }
            if (label == SUIT_ENVELOPE_LABEL_MANIFEST) {
                if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                    break;
                }
                errorCode = GetFilenameFromSuitManifest(filename, item.val.string, errorMessage);
                if (errorCode == TEEP_ERR_SUCCESS) {
                    break;
                }
                continue;
            }
        }
    }
    QCBORDecode_Finish(&context);
    return errorCode;
}

#if 0
// TODO(issue #7): implement SUIT processing.
// Parse a SUIT_Common out of a decode context and try to install it.
static teep_error_code_t TryProcessSuitCommon(UsefulBufC encoded, std::ostream& errorMessage)
{
    QCBORDecodeContext context;
    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORItem item;
    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        REPORT_TYPE_ERROR(errorMessage, "SUIT_Common", QCBOR_TYPE_MAP, item);
        return TEEP_ERR_PERMANENT_ERROR;
    }
    uint16_t mapEntryCount = item.val.uCount;

    for (int mapEntryIndex = 0; mapEntryIndex < mapEntryCount; mapEntryIndex++) {
        QCBORDecode_GetNext(&context, &item);
        suit_common_label_t label = (suit_common_label_t)item.label.int64;
        switch (label) {
        case SUIT_COMMON_LABEL_DEPENDENCIES:
        case SUIT_COMMON_LABEL_COMPONENTS:
        case SUIT_COMMON_LABEL_SEQUENCE:
            // Not yet implemented.
            return TEEP_ERR_TEMPORARY_ERROR;
            break;
        default:
            return TEEP_ERR_PERMANENT_ERROR;
        }
    }

    QCBORError err = QCBORDecode_Finish(&context);
    return (err == QCBOR_SUCCESS) ? TEEP_ERR_SUCCESS : TEEP_ERR_TEMPORARY_ERROR;
}
#endif

static teep_error_code_t SuitSaveManifest(
    _In_ filesystem::path& filename,
    _In_ UsefulBufC encoded,
    _Inout_ std::ostream& errorMessage)
{
    std::string path_str = filename.string();
    FILE* fp = fopen(path_str.c_str(), "wb");
    if (fp == nullptr) {
        return TEEP_ERR_MANIFEST_PROCESSING_FAILED;
    }
    fwrite(encoded.ptr, 1, encoded.len, fp);
    fclose(fp);
    return TEEP_ERR_SUCCESS;
}

// Parse a SUIT_Manifest out of a decode context and try to install it.
static teep_error_code_t TryProcessSuitManifest(_Inout_ filesystem::path& filename, UsefulBufC encoded, std::ostream& errorMessage)
{
#if 1
    TEEP_UNUSED(filename);
    TEEP_UNUSED(encoded);
    TEEP_UNUSED(errorMessage);
    return TEEP_ERR_SUCCESS;
#else
    QCBORDecodeContext context;
    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem item;
    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        REPORT_TYPE_ERROR(errorMessage, "SUIT_Manifest", QCBOR_TYPE_MAP, item);
        return TEEP_ERR_PERMANENT_ERROR;
    }
    int mapEntryCount = item.val.uCount;

    teep_error_code_t errorCode = TEEP_ERR_SUCCESS;
    for (int mapEntryIndex = 0; mapEntryIndex < mapEntryCount; mapEntryIndex++) {
        QCBORDecode_GetNext(&context, &item);
        if (errorCode != TEEP_ERR_SUCCESS) {
            continue;
        }
        suit_manifest_label_t label = (suit_manifest_label_t)item.label.int64;
        switch (label) {
        case SUIT_MANIFEST_LABEL_VERSION:
            if (item.uDataType != QCBOR_TYPE_INT64 || item.val.int64 != SUIT_MANIFEST_VERSION_VALUE) {
                REPORT_TYPE_ERROR(errorMessage, "suit-manifest-version", QCBOR_TYPE_INT64, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            break;
        case SUIT_MANIFEST_LABEL_SEQUENCE_NUMBER:
            if (item.uDataType != QCBOR_TYPE_INT64 && item.uDataType != QCBOR_TYPE_UINT64) {
                REPORT_TYPE_ERROR(errorMessage, "suit-manifest-sequence-number", QCBOR_TYPE_UINT64, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            break;
        case SUIT_MANIFEST_LABEL_COMMON:
            if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                REPORT_TYPE_ERROR(errorMessage, "suit-common", QCBOR_TYPE_BYTE_STRING, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
#if 0
            // TODO(issue #7): implement SUIT processing.
            errorCode = TryProcessSuitCommon(item.val.string, errorMessage);
#endif
            break;
        case SUIT_MANIFEST_LABEL_REFERENCE_URI:
        case SUIT_MANIFEST_LABEL_VALIDATE:
        case SUIT_MANIFEST_LABEL_LOAD:
        case SUIT_MANIFEST_LABEL_INVOKE:
        case 10: // obsolete
        case 11: // obsolete
        case 12: // obsolete
#if 0
            // TODO(issue #7): implement SUIT processing.
            errorCode = TEEP_ERR_TEMPORARY_ERROR;
#endif
            break;
        case SUIT_MANIFEST_LABEL_COMPONENT_ID:
            errorCode = GetFilenameFromSuitComponentIdentifier(filename, &context, &item, errorMessage);
            break;
        default:
            errorCode = TEEP_ERR_PERMANENT_ERROR;
        }
    }

    return errorCode;
#endif
}

// Parse a SUIT_Envelope out of a decode context and try to install it.
teep_error_code_t TryProcessSuitEnvelope(UsefulBufC encoded, std::ostream& errorMessage)
{
    // Try to extract a filename out of the SUIT envelope.
    filesystem::path filename;
    teep_error_code_t errorCode = GetFilenameFromSuitEnvelope(filename, encoded, errorMessage);
    if (errorCode != TEEP_ERR_SUCCESS) {
        return errorCode;
    }

    QCBORDecodeContext context;

    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem item;
    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        REPORT_TYPE_ERROR(errorMessage, "SUIT_Envelope", QCBOR_TYPE_MAP, item);
        return TEEP_ERR_PERMANENT_ERROR;
    }
    size_t mapEntryCount = item.val.uCount;

    for (size_t mapEntryIndex = 0; mapEntryIndex < mapEntryCount; mapEntryIndex++) {
        QCBORDecode_GetNext(&context, &item);
        if (errorCode != TEEP_ERR_SUCCESS) {
            continue;
        }
        suit_envelope_label_t label = (suit_envelope_label_t)item.label.int64;
        switch (label) {
        case SUIT_ENVELOPE_LABEL_AUTHENTICATION_WRAPPER:
            if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                REPORT_TYPE_ERROR(errorMessage, "suit-authentication-wrapper", QCBOR_TYPE_BYTE_STRING, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            // TODO: process authentication wrapper
            break;
        case SUIT_ENVELOPE_LABEL_MANIFEST:
            if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                REPORT_TYPE_ERROR(errorMessage, "suit-manifest", QCBOR_TYPE_BYTE_STRING, item);
                return TEEP_ERR_PERMANENT_ERROR;
            }
            errorCode = TryProcessSuitManifest(filename, item.val.string, errorMessage);
            break;
        default:
            errorCode = TEEP_ERR_PERMANENT_ERROR;
            break;
        }
    }

    if (errorCode == TEEP_ERR_SUCCESS) {
        errorCode = SuitSaveManifest(filename, encoded, errorMessage);
    }
    return errorCode;
}
