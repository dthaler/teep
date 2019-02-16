#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int strcasecmp(
    const char *string1,
    const char *string2)
{
    int cmp;

    for (size_t i = 0; ; i++)
    {
        int a = string1[i];
        int b = string2[i];
        if (!a && !b)
        {
            return 0; /* Equal. */
        }
        cmp = tolower(a) - tolower(b);
        if (cmp != 0)
        {
            return cmp; /* Not equal. */
        }
    }
    return 0; /* Equal. */
}

char* __cdecl strdup(const char* str)
{
    int len = strlen(str) + 1;
    char* result = (char*)malloc(len);
    if (result != NULL) {
        memcpy(result, str, len);
    }
    return result;
}
