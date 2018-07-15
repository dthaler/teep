/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#pragma once

int query_sgx_status(void);
int initialize_enclave(const char* token_filename, const char* enclave_filename);
