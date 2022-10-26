// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#pragma once

#define TA_UUID /* 94d75f35-541b-4ef0-a3f0-e8e87f29243c */ \
  {0x94d75f35,0x541b,0x4ef0,{0xa3,0xf0,0xe8,0xe8,0x7f,0x29,0x24,0x3c}}

#define TA_FLAGS                    (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE               (12 * 1024)        /* 12 KB */
#define TA_DATA_SIZE                (1 * 1024 * 1024)  /* 1 MB */

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
        "OTrPTamTA2 TA" }, \
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }
