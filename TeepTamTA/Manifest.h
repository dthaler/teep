#pragma once
class Manifest
{
public:
    static void AddManifest(oe_uuid_t component_id, const char* manifest_content, size_t manifest_content_size);
    static const char* GetManifest(UsefulBufC* component_id, size_t* manifest_size);

    Manifest* Next;

private:
    Manifest(oe_uuid_t component_id, const char* manifest, size_t manifest_size);

    oe_uuid_t _component_id;
    const char* _manifest;
    size_t _manifest_size;

    static Manifest* g_Manifest;
};

