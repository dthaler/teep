# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OE_SDK_PATH=../../packages/openenclave.0.2.0-CI-20190129-011410
OE_SDK_INC_PATH=$(OE_SDK_PATH)/build/native/include
OEEDGER8R=$(OE_SDK_PATH)/tools/oeedger8r

CFLAGS += $(EXTRA_CFLAGS)

CFLAGS +=                              \
    -I..                               \
    -I$(OE_SDK_INC_PATH)/new_platforms \
    -I$(OE_SDK_INC_PATH)

CFLAGS += -DLINUX -DOE_USE_OPTEE

libdirs += $(OE_SDK_PATH)/lib/native/gcc6/optee/v3.3.0/vexpress-qemu_armv8a

../OTrPCommonTALib2_t.c: ../OTrPCommonTALib2.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(OE_SDK_INC_PATH)" ../OTrPCommonTALib2.edl

../OTrPCommonTALib2_t.h: ../OTrPCommonTALib2.edl
	$(OEEDGER8R) --trusted --trusted-dir .. --search-path "$(OE_SDK_INC_PATH)" ../OTrPCommonTALib2.edl

# Add the c file generated from your EDL file here
srcs-y             += ../OTrPCommonTALib2_t.c

# Add additional sources here
srcs-y             += ../ecalls.c

libnames           += oeenclave
libnames           += oestdio_enc

# Add additional libraries here
# libnames         += ...
