/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
extern "C" {
#include "jansson.h"
};

class JsonAuto {
public:
    JsonAuto();
    JsonAuto(JsonAuto& value);
    JsonAuto(json_t* value, bool donateReference = false);
    ~JsonAuto();
    operator json_t*() {
        return ptr;
    }
    JsonAuto& operator =(json_t* value) {
        if (ptr != NULL) {
            json_decref(ptr);
        }
        ptr = json_incref(value);
    }
    json_t* AddStringToObject(const char* name, const char* value);
    json_t* AddObjectToObject(const char* name, json_t* obj = nullptr);
    json_t* AddArrayToObject(const char* name);
    json_t* AddObjectToArray();
private:
    json_t* ptr;
};
