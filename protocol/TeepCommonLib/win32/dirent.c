// Copyright (c) TEEP contributors
// SPDX-License-Identifier: MIT
#include <stdio.h>
#include "dirent.h"

DIR* opendir(_In_z_ const char* name)
{
    DIR* dir = malloc(sizeof(*dir));
    if (dir == NULL) {
        return NULL;
    }

    dir->pendingData = malloc(sizeof(*dir->pendingData));
    if (dir->pendingData == NULL) {
        free(dir);
        return NULL;
    }

    size_t length = strlen(name) + 3;
    char* filespec = malloc(length);
    if (filespec == NULL) {
        free(dir->pendingData);
        free(dir);
        return NULL;
    }
    sprintf_s(filespec, length, "%s/*", name);
    dir->hFindFile = FindFirstFileA(filespec, dir->pendingData);
    free(filespec);
    if (INVALID_HANDLE_VALUE == dir->hFindFile) {
        free(dir->pendingData);
        free(dir);
        return NULL;
    }

    return dir;
}

struct dirent* readdir(_In_ DIR* dirp)
{
    if (dirp->pendingData != NULL) {
        struct dirent* dirent = malloc(sizeof(*dirent));
        if (dirent == NULL) {
            return NULL;
        }
        strcpy_s(dirent->d_name, sizeof(dirent->d_name), dirp->pendingData->cFileName);
        free(dirp->pendingData);
        dirp->pendingData = NULL;
        return dirent;
    } else {
        WIN32_FIND_DATAA data;
        if (FindNextFileA(dirp->hFindFile, &data) == 0) {
            return NULL;
        }
        struct dirent* dirent = malloc(sizeof(*dirent));
        if (dirent == NULL) {
            return NULL;
        }
        strcpy_s(dirent->d_name, sizeof(dirent->d_name), data.cFileName);
        return dirent;
    }
}

int closedir(_In_ DIR* dirp)
{
    if (dirp == NULL) {
        return -1;
    }

    FindClose(dirp->hFindFile);
    free(dirp->pendingData);
    free(dirp);
    return 0;
}
