#pragma once
class Manifest
{
public:
    static void AddManifest(const char* taid, const char* manifest, size_t manifest_size);
    static const char* GetManifest(const char* taid, size_t* manifest_size);

private:
    Manifest(const char* taid, const char* manifest, size_t manifest_size);

    const char* _taid;
    const char* _manifest;
    size_t _manifest_size;

    static Manifest* g_Manifest;
};

