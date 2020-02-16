/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include "JsonAuto.h"

JsonAuto::JsonAuto() {
    ptr = NULL;
}

JsonAuto::JsonAuto(const JsonAuto& value) {
    ptr = json_incref(value);
}

JsonAuto::JsonAuto(json_t* value, bool donateReference)
{
    if (donateReference || !value) {
        ptr = value;
    } else {
        ptr = json_incref(value);
    }
}

JsonAuto::~JsonAuto() {
    if (ptr != NULL) {
        json_decref(ptr);
    }
}

json_t* JsonAuto::AddStringToObject(const char* name, const char* value) {
    JsonAuto str = json_string(value);
    if (str == NULL) {
        return NULL;
    }
    if (json_object_set(ptr, name, str)) {
        return NULL;
    }
    return str;
}

json_t* JsonAuto::AddObjectToObject(const char* name, json_t* obj) {
    if (obj == nullptr) {
        JsonAuto object = json_object();
        if (object == NULL) {
            return NULL;
        }
        if (json_object_set(ptr, name, object)) {
            return NULL;
        }
        return object;
    } else {
        if (json_object_set(ptr, name, obj)) {
            return NULL;
        }
        return obj;
    }
}

json_t* JsonAuto::AddArrayToObject(const char* name) {
    JsonAuto object = json_array();
    if (object == NULL) {
        return NULL;
    }
    if (json_object_set(ptr, name, object)) {
        return NULL;
    }
    return object;
}

json_t* JsonAuto::AddObjectToArray() {
    JsonAuto object = json_object();
    if (object == NULL) {
        return NULL;
    }
    if (json_array_append(ptr, object)) {
        return NULL;
    }
    return object;
}

json_t* JsonAuto::Detach(void)
{
    json_t* obj = ptr;
    ptr = NULL;
    return obj;
}

void JsonAuto::Attach(json_t* obj)
{
    ptr = obj;
}