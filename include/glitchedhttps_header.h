/*
   Copyright 2020 Raphael Beck

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
 *  @brief HTTP request (or response) header (for example: type="Authorization" ; value="Basic YWxhZGRpbjpvcGVuc2VzYW1l").
 */

#ifndef GLITCHEDHTTPS_HEADER_H
#define GLITCHEDHTTPS_HEADER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "glitchedhttps_api.h"
#include <stddef.h>

/**
 * @brief HTTP request (or response) header (for example: type="Authorization" ; value="Basic YWxhZGRpbjpvcGVuc2VzYW1l").
 */
struct glitchedhttps_header
{
    /**
     * The type of HTTP request header (its name without the ':' colon). E.g. "Authorization", "Server", etc... <p>
     * This MUST be a NUL-terminated C-string!
     */
    char* type;

    /**
     * The header value (what comes after the ':' colon separator). <p>
     * This MUST be a NUL-terminated C-string!
     */
    char* value;
};

/**
 * Creates and initializes a glitchedhttps_header instance and returns its pointer. <p>
 * @note Allocation is done for you: once you're done using this MAKE SURE to call {@link #glitchedhttps_header_free()} on it to prevent memory leaks!
 * @param type The header type name (e.g. "Authorization", "Accept", etc...). Must be a NUL-terminated string!
 * @param type_length The length of the header type string.
 * @param value The header value (NUL-terminated string).
 * @param value_length The length of the header value string.
 * @return The freshly allocated and initialized glitchedhttps_header instance (a pointer to it). If init failed, <code>NULL</code> is returned!
 */
GLITCHEDHTTPS_API struct glitchedhttps_header* glitchedhttps_header_init(const char* type, size_t type_length, const char* value, size_t value_length);

/**
 * Frees a glitchedhttps_header instance as well as its two heap-allocated strings inside.
 * @param header The glitchedhttps_header to deallocate.
 */
GLITCHEDHTTPS_API void glitchedhttps_header_free(struct glitchedhttps_header* header);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_HEADER_H
