/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include "joseinit.h"

void RAND_screen(void);
void jose_init_aescbch(void);
void jose_init_aeskw(void);
void jose_init_ec(void);
void jose_init_oct(void);
void jose_init_rsa(void);
void jose_init_ecdh(void);
void jose_init_ecdhes(void);
void jose_init_hash(void);
void jose_init_jwk(void);
void jose_init_rsassa(void);
void jose_init_rsaes(void);

void jose_init(void)
{
    jose_init_aescbch();
    jose_init_aeskw();
    jose_init_ec();
    jose_init_oct();
    jose_init_rsa();
    jose_init_rsaes();
    jose_init_rsassa();
    jose_init_ecdh();
    jose_init_ecdhes();
    jose_init_hash();
    jose_init_jwk();
    RAND_screen();
}
