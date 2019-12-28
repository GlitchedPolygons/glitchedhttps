/*
   Copyright 2019 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/**
 *  @file glitchedhttps_header.h
 *  @author Raphael Beck
 *  @date 28. December 2019
 *  @brief HTTP request (or response) header (for example: type="Authorization" ; value="Basic YWxhZGRpbjpvcGVuc2VzYW1l").
 */

#ifndef GLITCHEDHTTPS_HEADER_H
#define GLITCHEDHTTPS_HEADER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

/**
 * @brief HTTP request (or response) header (for example: type="Authorization" ; value="Basic YWxhZGRpbjpvcGVuc2VzYW1l").
 */
typedef struct glitchedhttps_header
{
    /** The type of HTTP request header (its name without the ':' colon). E.g. "Authorization", "Server", etc... */
    char* type;
    /** The header value (what comes after the ':' colon). */
    char* value;
} glitchedhttps_header;

/**
 * Creates and initializes a glitchedhttps_header instance and returns its pointer. <p>
 * Allocation is done for you: once you're done using this MAKE SURE to call {@link #glitchedhttps_header_free()} to prevent memory leaks!
 * @param type The header type name (e.g. "Authorization", "Accept", etc...). Must be a NUL-terminated string!
 * @param type_length The length of the header type string.
 * @param value The header value (NUL-terminated string).
 * @param value_length The length of the header value string.
 * @return The freshly allocated and initialized glitchedhttps_header instance (a pointer to it). If init failed, <code>NULL</code> is returned!
 */
static glitchedhttps_header* glitchedhttps_header_init(const char* type, const size_t type_length, const char* value, const size_t value_length)
{
    if (type == NULL || value == NULL)
    {
        _glitchedhttps_log_error("Header type or value string NULL!", __func__);
        return NULL;
    }

    if (type_length == 0)
    {
        _glitchedhttps_log_error("Header type string empty!", __func__);
        return NULL;
    }

    glitchedhttps_header* out = malloc(sizeof(glitchedhttps_header));
    if (out == NULL)
    {
        _glitchedhttps_log_error("OUT OF MEMORY!", __func__);
        return NULL;
    }

    out->type = malloc(sizeof(char) * type_length + 1);
    out->value = malloc(sizeof(char) * value_length + 1);

    if (out->type == NULL || out->value == NULL)
    {
        _glitchedhttps_log_error("OUT OF MEMORY!", __func__);
        return NULL;
    }

    memcpy(out->type, type, type_length);
    out->type[type_length] = '\0';

    if (value_length > 0)
    {
        memcpy(out->value, value, value_length);
        out->value[value_length] = '\0';
    }
    else
    {
        out->value[0] = '\0';
    }

    return out;
}

/**
 * Frees the glitchedhttps_header instance as well as its two heap-allocated strings inside.
 * @param header The glitchedhttps_header to deallocate.
 */
static inline void glitchedhttps_header_free(glitchedhttps_header* header)
{
    if (header != NULL)
    {
        free(header->type);
        free(header->value);
        free(header);
    }
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_HEADER_H
