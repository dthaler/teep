/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <openssl/ui.h>
#include <openssl/ossl_typ.h>
#include "crypto/ui/ui_locl.h"

static int open_console(UI *ui)
{
    return 0;
}

static int write_string(UI *ui, UI_STRING *uis)
{
    return 0;
}

static int read_string(UI *ui, UI_STRING *uis)
{
    return 0;
}

static int close_console(UI *ui)
{
    return 0;
}

static UI_METHOD otrp_ui_method = {
    (char *)"OTrP UI method",
    open_console,
    write_string,
    NULL,                       /* No flusher is needed for command lines */
    read_string,
    close_console,
    NULL
};

UI_METHOD *UI_OpenSSL(void)
{
    return &otrp_ui_method;
}
