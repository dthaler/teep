/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <sgx_trts.h>

#include <openssl/rand.h>

int RAND_poll(void)
{
    return (1);
}

/*
#define UINT unsigned int
#define WPARAM short
#define LPARAM long

int RAND_event(UINT iMsg, WPARAM wParam, LPARAM lParam)
{
    return (0);
}
*/

static int RAND_optee_bytes(unsigned char *buf, int num)
{
	sgx_status_t status = sgx_read_rand(buf, num);
	if (status != SGX_SUCCESS) {
		return 0;
	}

    // Positive numbers indicate success.
    return num;
}

RAND_METHOD rand_optee_meth = {
    NULL, // optee_rand_seed,
    RAND_optee_bytes,
    NULL, // optee_rand_cleanup,
    NULL, // optee_rand_add,
    RAND_optee_bytes, // optee_rand_pseudo_bytes,
    NULL  // optee_rand_status
};

void RAND_screen(void)
{
    RAND_set_rand_method(&rand_optee_meth);
}

#if 0
pid_t getpid(void)
{
    return 0x123;
}
#endif