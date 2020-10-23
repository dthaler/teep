#pragma once

// The values in this file are taken from
// https://tools.ietf.org/html/draft-ietf-suit-manifest

typedef enum {
    SUIT_ENVELOPE_LABEL_DELEGATION = 1,
    SUIT_ENVELOPE_LABEL_AUTHENTICATION_WRAPPER = 2,
    SUIT_ENVELOPE_LABEL_MANIFEST = 3
} suit_envelope_label_t;

typedef enum {
    SUIT_MANIFEST_LABEL_VERSION = 1,
    SUIT_MANIFEST_LABEL_SEQUENCE_NUMBER = 2,
    SUIT_MANIFEST_LABEL_COMMON = 3,
    SUIT_MANIFEST_LABEL_REFERENCE_URI = 4,
} suit_manifest_label_t;

typedef enum {
    SUIT_COMMON_LABEL_DEPENDENCIES = 1,
    SUIT_COMMON_LABEL_COMPONENTS = 2,
    SUIT_COMMON_LABEL_SEQUENCE = 4,
} suit_common_label_t;

#define SUIT_MANIFEST_VERSION_VALUE 1