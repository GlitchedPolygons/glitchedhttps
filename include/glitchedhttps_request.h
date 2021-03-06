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
 *  @file glitchedhttps_request.h
 *  @brief Struct containing an HTTP request's parameters and headers.
 */

#ifndef GLITCHEDHTTPS_REQUEST_H
#define GLITCHEDHTTPS_REQUEST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <string.h>
#include "glitchedhttps_api.h"
#include "glitchedhttps_method.h"

/**
 * @brief Struct containing an HTTP request's parameters and headers.
 */
struct glitchedhttps_request
{
    /**
     * The full, uncensored URL for the HTTP POST request including
     * protocol, host name, port (optional), resource URI and query parameters (if any).
     */
    char* url;

    /**
     * {@link #url} string length.
     */
    size_t url_length;

    /**
     * The request's HTTP method (E.g. GET, POST, ...).<p>
     * Please remember that only POST, PUT and PATCH requests
     * should send a request body (via <code>content</code> parameter here).
     */
    enum glitchedhttps_method method;

    /**
     * The HTTP request body.
     * Set this to <code>NULL</code> if you don't want to send a request body.<p>
     * Note that this is ignored for GET requests, as well as every other HTTP Method
     * that does not recommend the inclusion of a body... And if your server looks
     * for it nonetheless you're infringing the RFC2616 recommendation!<p>
     * @see https://tools.ietf.org/html/rfc2616#section-4.3
     * @see https://stackoverflow.com/a/983458
     */
    char* content;

    /**
     * Content-Length header that tells the server how many bytes to read from the message body. If this is zero, <code>strlen(content)</code> will be used!
     */
    size_t content_length;

    /**
     * The mime-type of the request body content (e.g. text/plain; charset=utf-8).
     */
    char* content_type;

    /**
     * {@link #content_type} string length.
     */
    size_t content_type_length;

    /**
     * The request body's encoding (e.g. "gzip").
     */
    char* content_encoding;

    /**
     * {@link #content_encoding} string length.
     */
    size_t content_encoding_length;

    /**
     * [OPTIONAL] Additional headers for the HTTP request. <p>
     * Set this to <code>NULL</code> if you don't want to add any additional HTTP request headers. <p>
     * You can create headers using the {@link #glitchedhttps_header_init()} function.
     */
    struct glitchedhttps_header* additional_headers;

    /**
     * The amount of passed additional HTTP request headers (pass zero if there's none).
     */
    size_t additional_headers_count;

    /**
     * How big should the underlying text buffer be?
     */
    size_t buffer_size;

    /**
     * @brief SET THIS TO FALSE! <p>
     * It's best to leave this set to <code>0</code>.<p>
     * Only set this to <code>1</code> if you don't want to enforce verification of the server's SSL certificate (DEFINITIVELY NOT RECOMMENDED FOR PRODUCTION ENV!).<p>
     * This value is only taken into consideration in case of an HTTPS request (determined by the scheme defined in the url). Plain HTTP requests ignore this setting.
     */
    int ssl_verification_optional;
};

/**
 * Initializes a glitchedhttps_request instance by setting its fields to their default value of zero/<code>NULL</code>.
 * @param request The glitchedhttps_request to initialize.
 */
static inline void glitchedhttps_request_init(struct glitchedhttps_request* request)
{
    if (request == NULL)
        return;

    memset(request, 0x00, sizeof(struct glitchedhttps_request));
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_REQUEST_H
