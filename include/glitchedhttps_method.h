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
 *  @file glitchedhttps_method.h
 *  @brief HTTP Method to use for a glitchedhttps_request
 */

#ifndef GLITCHEDHTTPS_METHOD_H
#define GLITCHEDHTTPS_METHOD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>
#include "glitchedhttps_debug.h"

/**
 * @brief HTTP Method to use for a glitchedhttps_request
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
 */
enum glitchedhttps_method
{
    GLITCHEDHTTPS_GET = 0,
    GLITCHEDHTTPS_HEAD = 1,
    GLITCHEDHTTPS_POST = 2,
    GLITCHEDHTTPS_PATCH = 3,
    GLITCHEDHTTPS_PUT = 4,
    GLITCHEDHTTPS_DELETE = 5,
    GLITCHEDHTTPS_CONNECT = 6,
    GLITCHEDHTTPS_OPTIONS = 7,
    GLITCHEDHTTPS_TRACE = 8
};

/**
 * Converts a glitchedhttps_method enum name to string. <p>
 * Make sure that you allocate at least a nice and sufficient <code>char[8]</code> for the out argument.
 * @param method The glitchedhttps_method to stringify.
 * @param out The out string into which to <code>strcpy()</code> the result (make sure to allocate at least 8 bytes).
 * @param out_size The size of the output <code>char*</code> buffer (must be greater than or equals 8).
 * @return Whether the passed glitchedhttps_method was converted to string successfully or not.
 */
bool glitchedhttps_method_to_string(enum glitchedhttps_method method, char* out, const size_t out_size);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_METHOD_H
