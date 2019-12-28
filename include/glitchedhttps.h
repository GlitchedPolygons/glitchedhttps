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
 *  @file glitchedhttps.h
 *  @author Raphael Beck
 *  @date 28. December 2019
 *  @brief Simple, lightweight and straight-forward way of doing HTTP(S) requests with the help of ARM's open-source MbedTLS library.
 *  @see https://github.com/GlitchedPolygons/glitchedhttps
 */

#ifndef GLITCHEDHTTPS_H
#define GLITCHEDHTTPS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <chillbuff.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/debug.h>
#include <mbedtls/platform.h>
#include <mbedtls/error.h>

#include <glitchedhttps_cacerts.h>

#ifdef WIN32
#include <winsock.h>
#endif

/** @private */
void (*_glitched_http_error_callback)(const char*) = NULL;

/** @private */
static inline void _glitched_http_log_error(const char* error, const char* origin)
{
    char error_msg[64 + strlen(error) + strlen(origin)];
    snprintf(error_msg, sizeof(error_msg), "\nGLITCHEDHTTPS ERROR: (%s) %s\n", origin, error);
    if (_glitched_http_error_callback != NULL)
    {
        _glitched_http_error_callback(error_msg);
    }
}

/**
 * Sets the glitchedhttps error callback. <p>
 * If errors occur, they'll be passed as a string into the provided callback function.
 * @param error_callback The function to call when errors occur.
 * @return Whether the callback was set up correctly or not (<code>bool</code> as defined in <code>stdbool.h</code>).
 */
static inline bool glitched_http_set_error_callback(void (*error_callback)(const char*))
{
    if (error_callback == NULL)
    {
        _glitched_http_log_error("The passed error callback is empty; Operation cancelled!", __func__);
        return false;
    }

    _glitched_http_error_callback = error_callback;
    return true;
}

/**
 * Clears the glitchedhttps error callback (errors won't be printed anymore).
 */
static inline void glitched_http_unset_error_callback()
{
    _glitched_http_error_callback = NULL;
}

/**
 * @brief HTTP request (or response) header (for example: type="Authorization" ; value="Basic YWxhZGRpbjpvcGVuc2VzYW1l").
 */
typedef struct glitched_http_header
{
    /** The type of HTTP request header (its name without the ':' colon). E.g. "Authorization", "Server", etc... */
    char* type;
    /** The header value (what comes after the ':' colon). */
    char* value;
} glitched_http_header;

/**
 * Creates and initializes a glitched_http_header instance and returns its pointer. <p>
 * Allocation is done for you: once you're done using this MAKE SURE to call {@link #glitched_http_header_free()} to prevent memory leaks!
 * @param type The header type name (e.g. "Authorization", "Accept", etc...). Must be a NUL-terminated string!
 * @param type_length The length of the header type string.
 * @param value The header value (NUL-terminated string).
 * @param value_length The length of the header value string.
 * @return The freshly allocated and initialized glitched_http_header instance (a pointer to it). If init failed, <code>NULL</code> is returned!
 */
static glitched_http_header* glitched_http_header_init(const char* type, const size_t type_length, const char* value, const size_t value_length)
{
    if (type == NULL || value == NULL)
    {
        // TODO: print error msg
        return NULL;
    }

    if (type_length == 0)
    {
        // TODO: print error msg "empty" here for type arg
        return NULL;
    }

    glitched_http_header* out = malloc(sizeof(glitched_http_header));
    if (out == NULL)
    {
        // TODO: print error msg "out of mem"
        return NULL;
    }

    out->type = malloc(sizeof(char) * type_length + 1);
    out->value = malloc(sizeof(char) * value_length + 1);

    if (out->type == NULL || out->value == NULL)
    {
        // TODO: print error msg "out of mem"
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
 * Frees the glitched_http_header instance as well as its two heap-allocated strings inside.
 * @param header The glitched_http_header to deallocate.
 */
static inline void glitched_http_header_free(glitched_http_header* header)
{
    if (header != NULL)
    {
        free(header->type);
        free(header->value);
        free(header);
    }
}

/* -------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------- */

/**
 * @brief HTTP Method to use for a glitched_http_request
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
 */
typedef enum glitched_http_method
{
    HTTP_GET = 0,
    HTTP_HEAD = 1,
    HTTP_POST = 2,
    HTTP_PATCH = 3,
    HTTP_PUT = 4,
    HTTP_DELETE = 5,
    HTTP_CONNECT = 6,
    HTTP_OPTIONS = 7,
    HTTP_TRACE = 8
} glitched_http_method;

/**
 * @brief Struct containing an HTTP request's parameters and headers.
 */
typedef struct glitched_http_request
{
    /**
     * The full, uncensored URL for the HTTP POST request including
     * protocol, host name, port (optional), resource URI and query parameters (if any).
     * MUST BE NUL-TERMINATED!
     */
    char* url;

    /**
     * The request's HTTP method (E.g. GET, POST, ...).<p>
     * Please remember that only POST, PUT and PATCH requests
     * should send a request body (via <code>content</code> parameter here).
     */
    glitched_http_method method;

    /**
     * The HTTP request body.
     * Set this to <code>NULL</code> if you don't want to send a request body.<p>
     * Note that this is ignored for GET requests, as well as every other glitched_http_method
     * that does not recommend the inclusion of a body... And if your server looks
     * for it nonetheless you're infringing the RFC2616 recommendation!<p>
     * @see https://tools.ietf.org/html/rfc2616#section-4.3
     * @see https://stackoverflow.com/a/983458
     */
    char* content;

    /**
     * The mime-type of the request body content (e.g. text/plain; charset=utf-8).
     */
    char* content_type;

    /**
     * The request body's encoding (e.g. "gzip").
     */
    char* content_encoding;

    /**
     * Content-Length header that tells the server how many bytes to read from the message body.
     */
    size_t content_length;

    /**
     * [OPTIONAL] Additional headers for the HTTP request. <p>
     * Set this to <code>NULL</code> if you don't want to add any additional HTTP request headers. <p>
     * You can create headers using the {@link #glitched_http_header_init()} function.
     */
    glitched_http_header* additional_headers;

    /**
     * The amount of passed additional HTTP request headers (pass zero if there's none).
     */
    size_t additional_headers_count;

    /**
     * How big should the underlying text buffer be?
     */
    size_t buffer_size;

    /**
     * It's best to leave this set to <code>false</code>.<p>
     * Only set this to <code>true</code> if you don't want to enforce verification of the server's SSL certificate (DEFINITIVELY NOT RECOMMENDED FOR PRODUCTION ENV!).<p>
     * This value is only taken into consideration in case of an HTTPS request (determined by the scheme defined in the url).
     */
    bool ssl_verification_optional;

} glitched_http_request;

/**
 * Converts an glitched_http_method enum name to string. <p>
 * Make sure that you allocate at least a nice and sufficient <code>char[8]</code> for the out argument.
 * @param method The glitched_http_method to stringify.
 * @param out The out string into which to <code>strcpy()</code> the result (make sure to allocate at least 8 bytes).
 * @param out_size The size of the output <code>char*</code> buffer (must be greater than or equals 8).
 * @return Whether the passed glitched_http_method was converted to string successfully or not.
 */
static inline bool glitched_http_method_to_string(const glitched_http_method method, char* out, const size_t out_size)
{
    if (out == NULL)
    {
        // TODO: print null arg error msg here.
        return false;
    }
    if (out_size < 8)
    {
        // TODO: print error here "Buffer size insufficient: please allocate at least 8 bytes!"
        return false;
    }
    switch (method)
    {
        case HTTP_GET:
            strncpy(out, "GET", out_size);
            return true;
        case HTTP_HEAD:
            strncpy(out, "HEAD", out_size);
            return true;
        case HTTP_POST:
            strncpy(out, "POST", out_size);
            return true;
        case HTTP_PATCH:
            strncpy(out, "PATCH", out_size);
            return true;
        case HTTP_PUT:
            strncpy(out, "PUT", out_size);
            return true;
        case HTTP_DELETE:
            strncpy(out, "DELETE", out_size);
            return true;
        case HTTP_CONNECT:
            strncpy(out, "CONNECT", out_size);
            return true;
        case HTTP_OPTIONS:
            strncpy(out, "OPTIONS", out_size);
            return true;
        case HTTP_TRACE:
            strncpy(out, "TRACE", out_size);
            return true;
        default:
            // TODO: print "Invalid HTTP Method!" here into error callback!
            return false;
    }
}

/* -------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------- */

/**
 * @brief Struct containing an HTTP response's data.
 */
typedef struct glitched_http_response
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

    /** All HTTP response headers. @see glitched_http_header */
    glitched_http_header* headers;

    /** The total amount of headers included in the HTTP response. */
    size_t headers_count;
} glitched_http_response;

/**
 * Frees an glitched_http_response instance that was allocated by {@link #glitched_http_submit()}.
 * @param response The glitched_http_response instance ready for deallocation.
 */
static void glitched_http_response_free(glitched_http_response* response)
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
        glitched_http_header_free(&(response->headers[i]));
    }

    free(response);
}

/* -------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------- */

/**
 * @brief Struct containing the output from a call to the {@link #glitched_http_new_guid()} function. <p>
 * 36 characters (only 32 if you chose to omit the hyphens) + 1 NUL terminator.
 */
typedef struct glitched_http_guid_string
{
    /** NUL-terminated string containing the GUID. */
    char string[36 + 1];
} glitched_http_guid_string;

#define GLITCHED_HTTP_GUID_LOWERCASE_HYPHENS "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"
#define GLITCHED_HTTP_GUID_LOWERCASE_NO_HYPHENS "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x"
#define GLITCHED_HTTP_GUID_UPPERCASE_HYPHENS "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X"
#define GLITCHED_HTTP_GUID_UPPERCASE_NO_HYPHENS "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X"

#define GLITCHED_HTTP_GET_GUID_FORMAT(lowercase, hyphens) ((lowercase) ? (hyphens) ? (GLITCHED_HTTP_GUID_LOWERCASE_HYPHENS) : (GLITCHED_HTTP_GUID_LOWERCASE_NO_HYPHENS) : (hyphens) ? (GLITCHED_HTTP_GUID_UPPERCASE_HYPHENS) : (GLITCHED_HTTP_GUID_UPPERCASE_NO_HYPHENS))

#ifdef _WIN32

/**
 * Generates a new GUID (a.k.a. UUID).
 * @param lowercase Should the GUID be lowercase or UPPERCASE only?
 * @param hyphens Should the GUID contain hyphen separators?
 * @return The glitched_http_guid_string
 */
glitched_http_guid_string glitched_http_new_guid(const bool lowercase, const bool hyphens)
{
    glitched_http_guid_string out;
    memset(out.string, '\0', sizeof(out.string));

    GUID guid = { 0 };
    CoCreateGuid(&guid);
    snprintf(out.string, sizeof(out.string), GLITCHED_HTTP_GET_GUID_FORMAT(lowercase, hyphens), guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return out;
}

#else

#include <uuid/uuid.h>
#include <netinet/in.h>
#include <netdb.h>

/**
 * Generates a new GUID (a.k.a. UUID).
 * @param lowercase Should the GUID be lowercase or UPPERCASE only?
 * @param hyphens Should the GUID contain hyphen separators?
 * @return The glitched_http_guid_string
 */
glitched_http_guid_string glitched_http_new_guid(const bool lowercase, const bool hyphens)
{
    glitched_http_guid_string out;
    memset(out.string, '\0', sizeof(out.string));

    uuid_t uuid;
    uuid_generate(uuid);

    char tmp[sizeof(out.string)];
    if (lowercase)
    {
        uuid_unparse_lower(uuid, tmp);
    }
    else
    {
        uuid_unparse_upper(uuid, tmp);
    }

    if (hyphens)
    {
        memcpy(out.string, tmp, sizeof(tmp));
    }
    else
    {
        char* c = out.string;
        for (int i = 0; i < sizeof(tmp); i++)
        {
            if (tmp[i] != '-')
            {
                *(c++) = tmp[i];
            }
        }
    }

    return out;
}

#endif

#undef GLITCHED_HTTP_GUID_LOWERCASE_HYPHENS
#undef GLITCHED_HTTP_GUID_LOWERCASE_NO_HYPHENS
#undef GLITCHED_HTTP_GUID_UPPERCASE_HYPHENS
#undef GLITCHED_HTTP_GUID_UPPERCASE_NO_HYPHENS
#undef GLITCHED_HTTP_GET_GUID_FORMAT

/* -------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------------------------------------------------- */

/** @private */
static void _glitched_http_debug(void* ctx, int level, const char* file, int line, const char* str)
{
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE*)ctx);
}

/* Needed for string comparisons ignoring case. */
/**
 * Compares two strings ignoring UPPER vs. lowercase.
 * @param str1 String to compare.
 * @param str2 String to compare to.
 * @param n How many characters of the string should be compared (starting from index 0)?
 * @return If the strings are equal, <code>0</code> is returned. Otherwise, something else.
 */
static inline int glitched_http_strncmpic(const char* str1, const char* str2, size_t n)
{
    size_t cmp = 0;
    int ret = INT_MIN;

    if (str1 == NULL || str2 == NULL)
    {
        return ret;
    }

    while ((*str1 || *str2) && cmp < n)
    {
        if ((ret = tolower((int)(*str1)) - tolower((int)(*str2))) != 0)
        {
            break;
        }
        cmp++;
        str1++;
        str2++;
    }

    return ret;
}

/**
 * Checks whether a given string starts with <code>http://</code>.
 * @param url The URL string to check.
 * @return Whether the passed URL has the http scheme at its beginning or not.
 */
static inline bool glitched_http_is_http(const char* url)
{
    return strlen(url) >= 7 && strncmp(url, "http://", 7) == 0;
}

/**
 * Checks whether a given string starts with <code>https://</code>.
 * @param url The URL string to check.
 * @return Whether the passed URL has the https scheme at its beginning or not.
 */
static inline bool glitched_http_is_https(const char* url)
{
    return strlen(url) >= 8 && strncmp(url, "https://", 8) == 0;
}

/**
 * Counts how many digits a number has.
 * @param number The number whose digit count you want to know.
 * @return The total amount of digits found.
 */
static inline size_t glitched_http_count_digits(const size_t number)
{
    size_t n = number, digits = 0;
    while (n != 0)
    {
        n /= 10;
        digits++;
    }
    return digits;
}

/** @private */
static glitched_http_response* _glitched_http_parse_response_string(const chillbuff* response_string)
{
    if (response_string == NULL)
    {
        return NULL;
    }

    /* Allocate the output http response struct and set pointers to default value "NULL".
     * The consumer of this returned value should not forget to call  on this! */
    glitched_http_response* out = malloc(sizeof(glitched_http_response));
    if (out == NULL)
    {
        _glitched_http_log_error("OUT OF MEMORY!", __func__);
        return NULL;
    }

    out->raw = NULL;
    out->date = NULL;
    out->server = NULL;
    out->headers = NULL;
    out->content = NULL;
    out->content_type = NULL;
    out->content_encoding = NULL;
    out->content_length = 0;
    out->headers_count = 0;
    out->status_code = -1;

    /* First of all, copy the whole, raw response string into the output. */
    out->raw = malloc((response_string->length + 1) * response_string->element_size);
    if (out->raw == NULL)
    {
        glitched_http_response_free(out);
        _glitched_http_log_error("OUT OF MEMORY!", __func__);
        return NULL;
    }

    memcpy(out->raw, response_string->array, response_string->length);
    out->raw[response_string->length] = '\0';

    /* Next comes the tedious parsing. */
    const char delimiter[] = "\r\n";
    const size_t delimiter_length = strlen(delimiter);

    const char content_delimiter[] = "\r\n\r\n";
    const size_t content_delimiter_length = strlen(content_delimiter);

    char* current = response_string->array;
    char* next = strstr(current, delimiter);

    bool parsed_status = false, parsed_server = false, parsed_date = false, parsed_content_type = false, parsed_content_encoding = false, parsed_content_length = false;

    chillbuff header_builder;
    chillbuff_init(&header_builder, 16, sizeof(glitched_http_header), CHILLBUFF_GROW_DUPLICATIVE);

    while (next != NULL)
    {
        const size_t current_length = next - current;

        if (!parsed_status && glitched_http_strncmpic(current, "HTTP/", 5) == 0)
        {
            char n[4];
            const char* c = memchr(current, ' ', current_length);
            if (c != NULL)
            {
                n[3] = '\0';
                memcpy(n, c + 1, 3);
                out->status_code = atoi(n);
            }
            parsed_status = true;
        }
        else if (!parsed_server && glitched_http_strncmpic(current, "Server: ", 8) == 0)
        {
            const size_t out_length = current_length - 8;
            out->server = malloc((out_length + 1) * sizeof(char));
            if (out->server == NULL)
            {
                _glitched_http_log_error("OUT OF MEMORY!", __func__);
                glitched_http_response_free(out);
                chillbuff_free(&header_builder);
                return NULL;
            }
            memcpy(out->server, current + 8, out_length);
            out->server[out_length] = '\0';
            chillbuff_push_back(&header_builder, glitched_http_header_init(current, 6, out->server, out_length), sizeof(glitched_http_header));
            parsed_server = true;
        }
        else if (!parsed_date && glitched_http_strncmpic(current, "Date: ", 6) == 0)
        {
            const size_t out_length = current_length - 6;
            out->date = malloc((out_length + 1) * sizeof(char));
            if (out->date == NULL)
            {
                _glitched_http_log_error("OUT OF MEMORY!", __func__);
                glitched_http_response_free(out);
                chillbuff_free(&header_builder);
                return NULL;
            }
            memcpy(out->date, current + 6, out_length);
            out->date[out_length] = '\0';
            chillbuff_push_back(&header_builder, glitched_http_header_init(current, 4, out->date, out_length), sizeof(glitched_http_header));
            parsed_date = true;
        }
        else if (!parsed_content_type && glitched_http_strncmpic(current, "Content-Type: ", 14) == 0)
        {
            const size_t out_length = current_length - 14;
            out->content_type = malloc((out_length + 1) * sizeof(char));
            if (out->content_type == NULL)
            {
                _glitched_http_log_error("OUT OF MEMORY!", __func__);
                glitched_http_response_free(out);
                chillbuff_free(&header_builder);
                return NULL;
            }
            memcpy(out->content_type, current + 14, out_length);
            out->content_type[out_length] = '\0';
            chillbuff_push_back(&header_builder, glitched_http_header_init(current, 12, out->content_type, out_length), sizeof(glitched_http_header));
            parsed_content_type = true;
        }
        else if (!parsed_content_encoding && glitched_http_strncmpic(current, "Content-Encoding: ", 18) == 0)
        {
            const size_t out_length = current_length - 18;
            out->content_encoding = malloc((out_length + 1) * sizeof(char));
            if (out->content_encoding == NULL)
            {
                _glitched_http_log_error("OUT OF MEMORY!", __func__);
                glitched_http_response_free(out);
                chillbuff_free(&header_builder);
                return NULL;
            }
            memcpy(out->content_encoding, current + 18, out_length);
            out->content_encoding[out_length] = '\0';
            chillbuff_push_back(&header_builder, glitched_http_header_init(current, 16, out->content_encoding, out_length), sizeof(glitched_http_header));
            parsed_content_encoding = true;
        }
        else if (!parsed_content_length && glitched_http_strncmpic(current, "Content-Length: ", 16) == 0)
        {
            char n[64];
            memset(n, '\0', sizeof(n));
            const char* c = memchr(current, ' ', current_length);
            if (c != NULL)
            {
                memcpy(n, c + 1, current_length - 1);
                out->content_length = atoi(n);
                snprintf(n, sizeof(n), "%lld", out->content_length);
                chillbuff_push_back(&header_builder, glitched_http_header_init(current, 14, n, strlen(n)), sizeof(glitched_http_header));
            }
            parsed_content_length = true;
        }
        else if (current != response_string->array && strncmp(current - delimiter_length, content_delimiter, content_delimiter_length) == 0)
        {
            const char* content = (current - delimiter_length) + content_delimiter_length;
            const size_t content_length = strlen(content);
            out->content = malloc(content_length + 1);
            if (out->content == NULL)
            {
                _glitched_http_log_error("OUT OF MEMORY!", __func__);
                glitched_http_response_free(out);
                chillbuff_free(&header_builder);
                return NULL;
            }
            memcpy(out->content, content, content_length);
            out->content[content_length] = '\0';
            break; // If the content (request body) was found, it's time to stop. Because there won't be anything else to come.
        }
        else
        {
            const char header_separator[] = ": ";
            const size_t header_separator_length = strlen(header_separator);

            const char* header_value = strstr(current, header_separator);
            if (header_value != NULL)
            {
                const size_t header_type_length = header_value - current;
                const size_t header_value_length = current_length - header_type_length - header_separator_length;
                chillbuff_push_back(&header_builder, glitched_http_header_init(current, header_type_length, header_value + header_separator_length, header_value_length), sizeof(glitched_http_header));
            }
        }
        current = next + delimiter_length;
        next = strstr(current, delimiter);
    }

    out->headers = malloc(sizeof(glitched_http_header) * header_builder.length); // TODO: copy headers array kinda here?!?!
    if (out->headers == NULL)
    {
        _glitched_http_log_error("OUT OF MEMORY!", __func__);
        glitched_http_response_free(out);
        chillbuff_free(&header_builder);
        return NULL;
    }

    chillbuff_free(&header_builder);

    return out;
}

/** @private */
static glitched_http_response* _glitched_http_https_request(const char* server_name, const int server_port, const char* request, const size_t buffer_size, const bool ssl_verification_optional)
{
    if (server_name == NULL || request == NULL || server_port <= 0)
    {
        _glitched_http_log_error("INVALID HTTPS parameters passed into \"_glitched_http_https_request\". Returning NULL...", __func__);
        return NULL;
    }

    glitched_http_response* out = NULL;

    chillbuff response_string;
    chillbuff_init(&response_string, 1024, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);

    uint32_t flags;
    int ret = 1, length;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    unsigned char buffer[buffer_size];

    time_t t;
    srand((unsigned)time(&t));

    glitched_http_guid_string guid = glitched_http_new_guid(rand() & 1, rand() & 1);

    mbedtls_x509_crt cacert;
    mbedtls_ssl_config ssl_config;
    mbedtls_ssl_context ssl_context;
    mbedtls_net_context net_context;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_net_init(&net_context);
    mbedtls_ssl_init(&ssl_context);
    mbedtls_ssl_config_init(&ssl_config);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    /* Seed the random number generator. */

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)guid.string, strlen(guid.string));
    if (ret != 0)
    {
        char msg[128];
        sprintf(msg, "HTTPS request failed: \"mbedtls_ctr_drbg_seed\" returned %d", ret);
        _glitched_http_log_error(msg, __func__);
        goto exit;
    }

    /* Load the CA root certificates. */

    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char*)GLITCHED_HTTP_CA_CERTS, sizeof(GLITCHED_HTTP_CA_CERTS));
    if (ret < 0)
    {
        char msg[128];
        sprintf(msg, "HTTPS request failed: \"mbedtls_x509_crt_parse\" returned -0x%x", -ret);
        _glitched_http_log_error(msg, __func__);
        goto exit;
    }

    /* Open the connection to the specified host. */

    char port[8];
    memset(port, '\0', sizeof(port));
    snprintf(port, sizeof(port), "%d", server_port);

    ret = mbedtls_net_connect(&net_context, server_name, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        char msg[128];
        sprintf(msg, "HTTPS request failed: \"mbedtls_net_connect\" returned %d", ret);
        _glitched_http_log_error(msg, __func__);
        goto exit;
    }

    /*  Set up the SSL/TLS structure. */

    ret = mbedtls_ssl_config_defaults(&ssl_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
    {
        char msg[128];
        sprintf(msg, "HTTPS request failed: \"mbedtls_ssl_config_defaults\" returned %d", ret);
        _glitched_http_log_error(msg, __func__);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&ssl_config, ssl_verification_optional ? MBEDTLS_SSL_VERIFY_OPTIONAL : MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&ssl_config, &cacert, NULL);
    mbedtls_ssl_conf_rng(&ssl_config, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&ssl_config, &_glitched_http_debug, stdout);

    ret = mbedtls_ssl_setup(&ssl_context, &ssl_config);
    if (ret != 0)
    {
        char msg[128];
        sprintf(msg, "HTTPS request failed: \"mbedtls_ssl_setup\" returned %d", ret);
        _glitched_http_log_error(msg, __func__);
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(&ssl_context, server_name);
    if (ret != 0)
    {
        char msg[128];
        sprintf(msg, "HTTPS request failed: \"mbedtls_ssl_set_hostname\" returned %d", ret);
        _glitched_http_log_error(msg, __func__);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl_context, &net_context, mbedtls_net_send, mbedtls_net_recv, NULL);

    /* SSL Handshake. */

    while ((ret = mbedtls_ssl_handshake(&ssl_context)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            char msg[128];
            sprintf(msg, "HTTPS request failed: \"mbedtls_ssl_handshake\" returned -0x%x", -ret);
            _glitched_http_log_error(msg, __func__);
            goto exit;
        }
    }

    /* Verify the server's X.509 certificate. */

    flags = mbedtls_ssl_get_verify_result(&ssl_context);
    if (flags != 0)
    {
        char verification_buffer[1024];
        mbedtls_x509_crt_verify_info(verification_buffer, sizeof(verification_buffer), "  ! ", flags);
        _glitched_http_log_error(verification_buffer, __func__);
        goto exit;
    }

    /* Write the request string.*/

    length = snprintf((char*)buffer, sizeof(buffer), "%s", request);

    while ((ret = mbedtls_ssl_write(&ssl_context, buffer, length)) <= 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            char msg[128];
            sprintf(msg, "HTTPS request failed: \"mbedtls_ssl_write\" returned %d", ret);
            _glitched_http_log_error(msg, __func__);
            goto exit;
        }
    }

    /* Read the HTTP response. */

    for (;;)
    {
        length = (int)(sizeof(buffer) - 1);
        memset(buffer, '\0', sizeof(buffer));
        ret = mbedtls_ssl_read(&ssl_context, buffer, length);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        {
            break;
        }

        if (ret < 0)
        {
            char msg[128];
            sprintf(msg, "HTTPS request failed: \"mbedtls_ssl_read\" returned %d", ret);
            _glitched_http_log_error(msg, __func__);
            break;
        }

        if (ret == 0)
        {
            /* EOF; ready to close the connection. */
            break;
        }

        length = ret;
        chillbuff_push_back(&response_string, buffer, length);
    }

    if (response_string.length == 0)
    {
        _glitched_http_log_error("HTTP response string empty!", __func__);
        goto exit;
    }

    out = _glitched_http_parse_response_string(&response_string);

    mbedtls_ssl_close_notify(&ssl_context);
    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#ifdef MBEDTLS_ERROR_C
    if (exit_code != MBEDTLS_EXIT_SUCCESS)
    {
        char error_buf[256];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        char msg[1024];
        sprintf(msg, "HTTPS request unsuccessful! Last error was: %d - %s", ret, error_buf);
        _glitched_http_log_error(msg, __func__);
    }
#endif

    mbedtls_net_free(&net_context);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl_context);
    mbedtls_ssl_config_free(&ssl_config);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    chillbuff_free(&response_string);

    return (out);
}

/** @private */
static glitched_http_response* _glitched_http_http_request(const char* server_name, const int server_port, const char* request, const size_t buffer_size)
{
    if (server_name == NULL || request == NULL || server_port <= 0)
    {
        _glitched_http_log_error("INVALID HTTP parameters passed into \"_glitched_http_http_request\". Returning NULL...", __func__);
        return NULL;
    }

    // struct hostent* server_host;
    // struct sockaddr_in server_addr;
    // int ret = -1, length, server_fd;
    // unsigned char buffer[buffer_size];
    // chillbuff response_string;
    // chillbuff_init(&response_string, 1024, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
//
///* Start the connection. */
//
// server_host = gethostbyname(server_name);
// if (server_host == NULL)
//{
//    _glitched_http_log_error("\"gethostbyname\" failed!", __func__);
//    goto exit;
//}
//
// server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
// if (server_fd < 0)
//{
//    char msg[128];
//    sprintf(msg, "HTTP request failed: \"socket\" returned %d", server_fd);
//    _glitched_http_log_error(msg, __func__);
//    goto exit;
//}
//
// memcpy((void*)&server_addr.sin_addr, (void*)server_host->h_addr, server_host->h_length);
//
// server_addr.sin_family = AF_INET;
// server_addr.sin_port = htons(server_port);
//
// ret = connect(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
// if (ret < 0)
//{
//    char msg[128];
//    sprintf(msg, "HTTP request failed: \"connect\" returned %d", ret);
//    _glitched_http_log_error(msg, __func__);
//    goto exit;
//}
//
///* Write the GET request. */
//
// length = sprintf((char*)buffer, "%s", request);
//
// while ((ret = write(server_fd, buffer, length)) <= 0)
//{
//    if (ret != 0)
//    {
//        char msg[128];
//        sprintf(msg, "HTTP request failed: \"write\" returned %d", ret);
//        _glitched_http_log_error(msg, __func__);
//        goto exit;
//    }
//}
//
///* Read the HTTP response. */
//
// for (;;)
//{
//    length = (int)(sizeof(buffer) - 1);
//    memset(buffer, 0, sizeof(buffer));
//    ret = read(server_fd, buffer, length);
//
//    if (ret <= 0)
//    {
//        char msg[128];
//        sprintf(msg, "HTTP request failed: \"read\" returned %d", ret);
//        _glitched_http_log_error(msg, __func__);
//        break;
//    }
//
//    length = ret;
//    chillbuff_push_back(&response_string, buffer, length);
//}
//
//// TODO: return response accordingly (and correctly!)
//
exit:
    //
    // chillbuff_free(&response_string);
    // close(server_fd);
    //
    return NULL;
}

/**
 * Submits a given HTTP request and returns the server response. <p>
 * This allocates memory, so don't forget to {@link #glitched_http_response_free()} the returned glitched_http_response instance after usage!!
 * @param request The glitched_http_request instance containing the request parameters and data (e.g. url, body, etc...).
 * @return The (freshly allocated) glitched_http_response instance containing the response headers, status code, etc... if the request was submitted successfully; <code>NULL</code> if the request couldn't even be submitted (e.g. invalid URL/server not found/no internet/whatever..).
 */
glitched_http_response* glitched_http_submit(const glitched_http_request* request)
{
    if (request->url == NULL)
    {
        _glitched_http_log_error("URL parameter NULL!", __func__);
        return NULL;
    }

    const bool https = glitched_http_is_https(request->url);
    const char* server_host_ptr = https ? request->url + 8 : glitched_http_is_http(request->url) ? request->url + 7 : NULL;

    if (server_host_ptr == NULL)
    {
        _glitched_http_log_error("Missing or invalid protocol in passed URL: needs \"http://\" or \"https://\"", __func__);
        return NULL;
    }

    char server_host[256];
    memset(server_host, '\0', sizeof(server_host));

    char* path = strchr(server_host_ptr, '/');
    strncpy(server_host, server_host_ptr, path == NULL ? strlen(server_host_ptr) : path - server_host_ptr);

    int server_port = https ? 443 : 80;

    char* custom_port = strrchr(server_host, ':');
    if (custom_port != NULL)
    {
        /* IPv6 safety check. */
        if (*server_host_ptr != '[' || *(custom_port - 1) == ']')
        {
            server_port = atoi(custom_port + 1);
            if (server_port <= 0 || server_port >= 65536)
            {
                char msg[128];
                sprintf(msg, "Invalid port number \"%d\"", server_port);
                _glitched_http_log_error(msg, __func__);
                return NULL;
            }
            memset(custom_port, '\0', strlen(custom_port));
        }
        else
        {
            custom_port = NULL;
        }
    }

    if (path == NULL)
        path = "/";

    char method[8];
    if (!glitched_http_method_to_string(request->method, method, sizeof(method)))
    {
        _glitched_http_log_error("HTTP request submission rejected due to invalid HTTP method name.", __func__);
        return NULL;
    }
    method[sizeof(method) - 1] = '\0';

    chillbuff request_string;
    chillbuff_init(&request_string, 1024, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);

    char tmp[64 + strlen(method) + strlen(path) + strlen(server_host)];
    snprintf(tmp, sizeof(tmp), "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: Close\r\n", method, path, server_host);
    chillbuff_push_back(&request_string, tmp, strlen(tmp));
    memset(tmp, '\0', sizeof(tmp));

    for (size_t i = 0; i < request->additional_headers_count; i++)
    {
        glitched_http_header header = request->additional_headers[i];
        char header_string[16 + strlen(header.type) + strlen(header.value)];
        snprintf(header_string, sizeof(header_string), "%s: %s\r\n", header.type, header.value);
        chillbuff_push_back(&request_string, header_string, strlen(header_string));
        memset(header_string, '\0', sizeof(header_string));
    }

    if (request->content != NULL && request->content_type != NULL && request->content_length > 0)
    {
        const size_t content_length = strlen(request->content);
        if (content_length > 0)
        {
            char content_headers[64 + strlen(request->content_type) + glitched_http_count_digits(request->content_length) + content_length];
            snprintf(content_headers, sizeof(content_headers), "Content-Type: %s\r\nContent-Length: %zu\r\n\r\n%s\r\n", request->content_type, request->content_length, request->content);
            chillbuff_push_back(&request_string, content_headers, strlen(content_headers));
            memset(content_headers, '\0', sizeof(content_headers));

            if (request->content_encoding != NULL)
            {
                const size_t content_encoding_length = strlen(request->content_encoding);
                if (content_encoding_length > 0)
                {
                    char encoding[64 + content_encoding_length];
                    snprintf(encoding, sizeof(encoding), "Content-Encoding: %s\r\n", request->content_encoding);
                    chillbuff_push_back(&request_string, encoding, strlen(encoding));
                    memset(encoding, '\0', sizeof(encoding));
                }
            }
        }
    }

    chillbuff_push_back(&request_string, "\r\n", strlen("\r\n"));

    glitched_http_response* out = https ? _glitched_http_https_request(server_host, server_port, request_string.array, request->buffer_size, request->ssl_verification_optional) : _glitched_http_http_request(server_host, server_port, request_string.array, request->buffer_size);
    chillbuff_free(&request_string);
    return out;
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_H
