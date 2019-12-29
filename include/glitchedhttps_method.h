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
 *  @file glitchedhttps_method.h
 *  @author Raphael Beck
 *  @date 28. December 2019
 *  @brief HTTP Method to use for a glitchedhttps_request
 */

#ifndef GLITCHEDHTTPS_METHOD_H
#define GLITCHEDHTTPS_METHOD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include "glitchedhttps_debug.h"

/**
 * @brief HTTP Method to use for a glitchedhttps_request
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
 */
typedef enum glitchedhttps_method
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
} glitchedhttps_method;

/**
 * Converts a glitchedhttps_method enum name to string. <p>
 * Make sure that you allocate at least a nice and sufficient <code>char[8]</code> for the out argument.
 * @param method The glitchedhttps_method to stringify.
 * @param out The out string into which to <code>strcpy()</code> the result (make sure to allocate at least 8 bytes).
 * @param out_size The size of the output <code>char*</code> buffer (must be greater than or equals 8).
 * @return Whether the passed glitchedhttps_method was converted to string successfully or not.
 */
bool glitchedhttps_method_to_string(const glitchedhttps_method method, char* out, const size_t out_size)
{
    if (out == NULL)
    {
        _glitchedhttps_log_error("Pointer argument \"out\" is NULL! Please provide a valid output string to write (strncpy) into.", __func__);
        return false;
    }
    if (out_size < 8)
    {
        _glitchedhttps_log_error("Insufficient output buffer size: please allocate at least 8 bytes for the out string!", __func__);
        return false;
    }
    switch (method)
    {
        case GLITCHEDHTTPS_GET:
            strncpy(out, "GET", out_size);
            return true;
        case GLITCHEDHTTPS_HEAD:
            strncpy(out, "HEAD", out_size);
            return true;
        case GLITCHEDHTTPS_POST:
            strncpy(out, "POST", out_size);
            return true;
        case GLITCHEDHTTPS_PATCH:
            strncpy(out, "PATCH", out_size);
            return true;
        case GLITCHEDHTTPS_PUT:
            strncpy(out, "PUT", out_size);
            return true;
        case GLITCHEDHTTPS_DELETE:
            strncpy(out, "DELETE", out_size);
            return true;
        case GLITCHEDHTTPS_CONNECT:
            strncpy(out, "CONNECT", out_size);
            return true;
        case GLITCHEDHTTPS_OPTIONS:
            strncpy(out, "OPTIONS", out_size);
            return true;
        case GLITCHEDHTTPS_TRACE:
            strncpy(out, "TRACE", out_size);
            return true;
        default:
            _glitchedhttps_log_error("Invalid HTTP Method!", __func__);
            return false;
    }
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_METHOD_H
