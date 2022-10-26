// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#endif
#include <stdlib.h>
extern "C" {
#include "teep_protocol.h"
#include "suit_manifest.h"
};
#include "common.h"
#include "qcbor/qcbor_decode.h"
#include "SuitParser.h"

// Parse a SUIT_Common out of a decode context and try to install it.
teep_error_code_t TryProcessSuitCommon(UsefulBufC encoded, std::ostream& errorMessage)
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

// Parse a SUIT_Manifest out of a decode context and try to install it.
teep_error_code_t TryProcessSuitManifest(UsefulBufC encoded, std::ostream& errorMessage)
{
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
            errorCode = TryProcessSuitCommon(item.val.string, errorMessage);
            break;
        case SUIT_MANIFEST_LABEL_REFERENCE_URI:
            errorCode = TEEP_ERR_TEMPORARY_ERROR;
            break;
        default:
            errorCode = TEEP_ERR_PERMANENT_ERROR;
        }
    }
    return errorCode;
}

// Parse a SUIT_Envelope out of a decode context and try to install it.
teep_error_code_t TryProcessSuitEnvelope(UsefulBufC encoded, std::ostream& errorMessage)
{
    QCBORDecodeContext context;

    QCBORDecode_Init(&context, encoded, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem item;
    QCBORDecode_GetNext(&context, &item);
    if (item.uDataType != QCBOR_TYPE_MAP) {
        REPORT_TYPE_ERROR(errorMessage, "SUIT_Envelope", QCBOR_TYPE_MAP, item);
        return TEEP_ERR_PERMANENT_ERROR;
    }
    size_t mapEntryCount = item.val.uCount;

    teep_error_code_t errorCode = TEEP_ERR_SUCCESS;
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
            errorCode = TryProcessSuitManifest(item.val.string, errorMessage);
            break;
        default:
            errorCode = TEEP_ERR_PERMANENT_ERROR;
            break;
        }
    }
    return errorCode;
}
