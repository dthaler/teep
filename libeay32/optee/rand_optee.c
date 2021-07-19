// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <openssl/rand.h>

int RAND_poll(void)
{
    return (1);
}

static int RAND_otrp_bytes(unsigned char *buf, int num)
{
    oe_result_t result = oe_random(buf, num);
	if (result != OE_OK) {
		return 0;
	}

    // Positive numbers indicate success.
    return num;
}

RAND_METHOD rand_otrp_meth = {
    NULL, // otrp_rand_seed,
    RAND_otrp_bytes,
    NULL, // otrp_rand_cleanup,
    NULL, // otrp_rand_add,
    RAND_otrp_bytes, // otrp_rand_pseudo_bytes,
    NULL  // otrp_rand_status
};

void RAND_screen(void)
{
    RAND_set_rand_method(&rand_otrp_meth);
}
