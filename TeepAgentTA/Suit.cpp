/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openenclave/enclave.h>
#include <stdlib.h>
extern "C" {
#include "jansson.h"
#include "../TeepCommonTALib/common.h"
};
#include "qcbor/qcbor_decode.h"
#include "Suit.h"

// Parse a SUIT_Common out of a decode context and try to install it.
teep_error_code_t TryProcessSuitCommon(QCBORDecodeContext* context, uint16_t mapEntryCount)
{
    QCBORItem item;
    teep_error_code_t errorCode = TEEP_ERR_SUCCESS;
    for (int mapEntryIndex = 0; mapEntryIndex < mapEntryCount; mapEntryIndex++) {
        QCBORDecode_GetNext(context, &item);
        if (errorCode != TEEP_ERR_SUCCESS) {
            continue;
        }
        suit_common_label_t label = (suit_common_label_t)item.label.int64;
        switch (label) {
        case SUIT_COMMON_LABEL_DEPENDENCIES:
        case SUIT_COMMON_LABEL_COMPONENTS:
        case SUIT_COMMON_LABEL_SEQUENCE:
            // Not yet implemented.
            errorCode = TEEP_ERR_INTERNAL_ERROR;
            break;
        default:
            errorCode = TEEP_ERR_ILLEGAL_PARAMETER;
        }
    }
    return errorCode;
}

// Parse a SUIT_Manifest out of a decode context and try to install it.
teep_error_code_t TryProcessSuitManifest(QCBORDecodeContext* context, uint16_t mapEntryCount)
{
    QCBORItem item;
    teep_error_code_t errorCode = TEEP_ERR_SUCCESS;
    for (int mapEntryIndex = 0; mapEntryIndex < mapEntryCount; mapEntryIndex++) {
        QCBORDecode_GetNext(context, &item);
        if (errorCode != TEEP_ERR_SUCCESS) {
            continue;
        }
        suit_manifest_label_t label = (suit_manifest_label_t)item.label.int64;
        switch (label) {
        case SUIT_MANIFEST_LABEL_VERSION:
            if (item.uDataType != QCBOR_TYPE_INT64 || item.val.int64 != SUIT_MANIFEST_VERSION_VALUE) {
                printf("Invalid suit-manifest-version\n");
                return TEEP_ERR_ILLEGAL_PARAMETER; /* invalid message */
            }
            break;
        case SUIT_MANIFEST_LABEL_SEQUENCE_NUMBER:
            if (item.uDataType != QCBOR_TYPE_UINT64) {
                printf("Invalid suit-manifest-sequence-number type %d\n", item.uDataType);
                return TEEP_ERR_ILLEGAL_PARAMETER; /* invalid message */
            }
            break;
        case SUIT_MANIFEST_LABEL_COMMON:
            if (item.uDataType != QCBOR_TYPE_MAP) {
                printf("Invalid suit-manifest-common type %d\n", item.uDataType);
                return TEEP_ERR_ILLEGAL_PARAMETER; /* invalid message */
            }
            errorCode = TryProcessSuitCommon(context, item.val.uCount);
            break;
        case SUIT_MANIFEST_LABEL_REFERENCE_URI:
            errorCode = TEEP_ERR_INTERNAL_ERROR;
            break;
        default:
            errorCode = TEEP_ERR_ILLEGAL_PARAMETER;
        }
    }
    return errorCode;
}

// Parse a SUIT_Envelope out of a decode context and try to install it.
teep_error_code_t TryProcessSuitEnvelope(QCBORDecodeContext* context, size_t mapEntryCount)
{
    QCBORItem item;
    teep_error_code_t errorCode = TEEP_ERR_SUCCESS;
    for (size_t mapEntryIndex = 0; mapEntryIndex < mapEntryCount; mapEntryIndex++) {
        QCBORDecode_GetNext(context, &item);
        if (errorCode != TEEP_ERR_SUCCESS) {
            continue;
        }
        suit_envelope_label_t label = (suit_envelope_label_t)item.label.int64;
        switch (label) {
        case SUIT_ENVELOPE_LABEL_AUTHENTICATION_WRAPPER:
            // TODO: process authentication wrapper
            break;
        case SUIT_ENVELOPE_LABEL_MANIFEST:
            if (item.uDataType != QCBOR_TYPE_MAP) {
                printf("Invalid SUIT_Envelope type %d\n", item.uDataType);
                return TEEP_ERR_ILLEGAL_PARAMETER; /* invalid message */
            }
            errorCode = TryProcessSuitManifest(context, item.val.uCount);
            break;
        default:
            errorCode = TEEP_ERR_ILLEGAL_PARAMETER;
            break;
        }
    }
    return errorCode;
}
