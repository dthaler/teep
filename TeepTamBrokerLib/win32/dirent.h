#pragma once
#include <Windows.h>

#ifdef _cplusplus
extern "C"
{
#endif

    typedef struct _DIR {
        HANDLE hFindFile;
        WIN32_FIND_DATAA* pendingData;
    } DIR;

    struct dirent {
        char d_name[256]; /* filename */
    };

    DIR* opendir(_In_z_ const char* name);
    struct dirent* readdir(_In_ DIR* dirp);
    int closedir(_In_ DIR* dirp);

#ifdef _cplusplus
}
#endif