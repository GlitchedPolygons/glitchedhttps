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
 *  @file glitchedhttps_response.h
 *  @author Raphael Beck
 *  @date 28. December 2019
 *  @brief Struct containing an HTTP response's data.
 */

#ifndef GLITCHEDHTTPS_RESPONSE_H
#define GLITCHEDHTTPS_RESPONSE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include "glitchedhttps_header.h"

/**
 * @brief Struct containing an HTTP response's data.
 */
typedef struct glitchedhttps_response
{
    /** The result status code (e.g. 200 for "OK", 404 for "Not Found", etc...). */
    int status_code;

    /** The full, raw returned HTTP response in plain text, with carriage returns, line breaks, final NUL-terminator and everything... */
    char* raw;

    /** The (NUL-terminated) response's server header string. */
    char* server;

    /** Response timestamp in GMT (original string, with NUL-terminator at its end). */
    char* date;

    /** Response body content type (e.g. "text/plain; charset=utf-8"). NUL-terminated. If there's no response body, this remains <code>NULL</code>. */
    char* content_type;

    /** Response body encoding (e.g. "gzip"). NUL-terminated string. If there's no response body, this remains <code>NULL</code>. */
    char* content_encoding;

    /** The response's content body (could be a JSON string, could be plain text; make sure to check out and acknowledge the "content_type" field before doing anything with this). */
    char* content;

    /** The response's content length header value. */
    size_t content_length;

    /** All HTTP response headers. @see glitchedhttps_header */
    glitchedhttps_header* headers;

    /** The total amount of headers included in the HTTP response. */
    size_t headers_count;
} glitchedhttps_response;

/**
 * Frees an glitchedhttps_response instance that was allocated by {@link #glitchedhttps_submit()}.
 * @param response The glitchedhttps_response instance ready for deallocation.
 */
static void glitchedhttps_response_free(glitchedhttps_response* response)
{
    if (response == NULL)
    {
        return;
    }

    free(response->raw);
    response->raw = NULL;

    free(response->server);
    response->server = NULL;

    free(response->date);
    response->date = NULL;

    free(response->content);
    response->content = NULL;

    free(response->content_type);
    response->content_type = NULL;

    free(response->content_encoding);
    response->content_encoding = NULL;

    for (size_t i = 0; i < response->headers_count; i++)
    {
        glitchedhttps_header* h = &(response->headers[i]);
        glitchedhttps_header_free(h);
    }

    free(response);
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_RESPONSE_H
