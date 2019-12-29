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
#include <chillbuff.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/debug.h>
#include <mbedtls/platform.h>
#include <mbedtls/error.h>

#include "glitchedhttps_cacerts.h"
#include "glitchedhttps_strutil.h"
#include "glitchedhttps_debug.h"
#include "glitchedhttps_guid.h"
#include "glitchedhttps_method.h"
#include "glitchedhttps_header.h"
#include "glitchedhttps_request.h"
#include "glitchedhttps_response.h"

#ifdef WIN32
#include <winsock.h>
#endif

/**
 * Returned from a glitchedhttps function when everything went as expected.
 */
#define GLITCHEDHTTPS_SUCCESS 0

/**
 * If you get this, it means you're out of memory!
 */
#define GLITCHEDHTTPS_OUT_OF_MEM 100

/**
 * Error code returned by a glitchedhttps function if you passed a NULL argument that shouldn't have been NULL.
 */
#define GLITCHEDHTTPS_NULL_ARG 200

/**
 * This error code is returned by a glitchedhttps function if you passed an invalid parameter into it.
 */
#define GLITCHEDHTTPS_INVALID_ARG 300

/**
 * Returned when the request URL has an invalid port number.
 */
#define GLITCHEDHTTPS_INVALID_PORT_NUMBER 400

/**
 * Returned if the given HTTP method is not one of the allowed ones (e.g. <code>GET</code>, <code>POST</code>, etc...).
 */
#define GLITCHEDHTTPS_INVALID_HTTP_METHOD_NAME 500

/**
 * When something fails that has nothing to do with glitchedhttps (e.g. if the chillbuff init function fails for some reason and the http request function can't proceed without a stringbuilder).
 */
#define GLITCHEDHTTPS_EXTERNAL_ERROR 600

/** @private */
static glitchedhttps_response* _glitchedhttps_parse_response_string(const chillbuff* response_string)
{
    if (response_string == NULL)
    {
        return NULL;
    }

    /* Allocate the output http response struct and set pointers to default value "NULL".
     * The consumer of this returned value should not forget to call  on this! */
    glitchedhttps_response* out = malloc(sizeof(glitchedhttps_response));
    if (out == NULL)
    {
        _glitchedhttps_log_error("OUT OF MEMORY!", __func__);
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
        glitchedhttps_response_free(out);
        _glitchedhttps_log_error("OUT OF MEMORY!", __func__);
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
    chillbuff_init(&header_builder, 16, sizeof(glitchedhttps_header), CHILLBUFF_GROW_DUPLICATIVE);

    while (next != NULL)
    {
        const size_t current_length = next - current;

        if (!parsed_status && glitchedhttps_strncmpic(current, "HTTP/", 5) == 0)
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
        else if (!parsed_server && glitchedhttps_strncmpic(current, "Server: ", 8) == 0)
        {
            const size_t out_length = current_length - 8;
            out->server = malloc((out_length + 1) * sizeof(char));
            if (out->server == NULL)
            {
                goto out_of_mem;
            }
            memcpy(out->server, current + 8, out_length);
            out->server[out_length] = '\0';
            chillbuff_push_back(&header_builder, glitchedhttps_header_init(current, 6, out->server, out_length), 1);
            parsed_server = true;
        }
        else if (!parsed_date && glitchedhttps_strncmpic(current, "Date: ", 6) == 0)
        {
            const size_t out_length = current_length - 6;
            out->date = malloc((out_length + 1) * sizeof(char));
            if (out->date == NULL)
            {
                goto out_of_mem;
            }
            memcpy(out->date, current + 6, out_length);
            out->date[out_length] = '\0';
            chillbuff_push_back(&header_builder, glitchedhttps_header_init(current, 4, out->date, out_length), 1);
            parsed_date = true;
        }
        else if (!parsed_content_type && glitchedhttps_strncmpic(current, "Content-Type: ", 14) == 0)
        {
            const size_t out_length = current_length - 14;
            out->content_type = malloc((out_length + 1) * sizeof(char));
            if (out->content_type == NULL)
            {
                goto out_of_mem;
            }
            memcpy(out->content_type, current + 14, out_length);
            out->content_type[out_length] = '\0';
            chillbuff_push_back(&header_builder, glitchedhttps_header_init(current, 12, out->content_type, out_length), 1);
            parsed_content_type = true;
        }
        else if (!parsed_content_encoding && glitchedhttps_strncmpic(current, "Content-Encoding: ", 18) == 0)
        {
            const size_t out_length = current_length - 18;
            out->content_encoding = malloc((out_length + 1) * sizeof(char));
            if (out->content_encoding == NULL)
            {
                goto out_of_mem;
            }
            memcpy(out->content_encoding, current + 18, out_length);
            out->content_encoding[out_length] = '\0';
            chillbuff_push_back(&header_builder, glitchedhttps_header_init(current, 16, out->content_encoding, out_length), 1);
            parsed_content_encoding = true;
        }
        else if (!parsed_content_length && glitchedhttps_strncmpic(current, "Content-Length: ", 16) == 0)
        {
            char n[64];
            memset(n, '\0', sizeof(n));
            const char* c = memchr(current, ' ', current_length);
            if (c != NULL)
            {
                memcpy(n, c + 1, current_length - 1);
                out->content_length = atoi(n);
                snprintf(n, sizeof(n), "%zu", out->content_length);
                chillbuff_push_back(&header_builder, glitchedhttps_header_init(current, 14, n, strlen(n)), 1);
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
                goto out_of_mem;
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
                chillbuff_push_back(&header_builder, glitchedhttps_header_init(current, header_type_length, header_value + header_separator_length, header_value_length), 1);
            }
        }
        current = next + delimiter_length;
        next = strstr(current, delimiter);
    }

    out->headers = malloc(sizeof(glitchedhttps_header) * header_builder.length);
    if (out->headers == NULL)
    {
        goto out_of_mem;
    }

    /* Copy the response headers into the output instance. */
    out->headers_count = header_builder.length;
    for (size_t i = 0; i < header_builder.length; i++)
    {
        const glitchedhttps_header h = ((glitchedhttps_header*)header_builder.array)[i];
        out->headers[i] = *glitchedhttps_header_init(h.type, strlen(h.type), h.value, strlen(h.value));
    }

    chillbuff_free(&header_builder);

    return out;

out_of_mem:
    _glitchedhttps_log_error("OUT OF MEMORY!", __func__);
    glitchedhttps_response_free(out);
    chillbuff_free(&header_builder);
    return NULL;
}

/** @private */
static glitchedhttps_response* _glitchedhttps_https_request(const char* server_name, const int server_port, const char* request, const size_t buffer_size, const bool ssl_verification_optional)
{
    if (server_name == NULL || request == NULL || server_port <= 0)
    {
        _glitchedhttps_log_error("INVALID HTTPS parameters passed into \"_glitchedhttps_https_request\". Returning NULL...", __func__);
        return NULL;
    }

    glitchedhttps_response* out = NULL;

    chillbuff response_string;
    chillbuff_init(&response_string, 1024, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);

    uint32_t flags;
    int ret = 1, length;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    unsigned char buffer[buffer_size];

    time_t t;
    srand((unsigned)time(&t));

    glitchedhttps_guid guid = glitchedhttps_new_guid(rand() & 1, rand() & 1);

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
        _glitchedhttps_log_error(msg, __func__);
        goto exit;
    }

    /* Load the CA root certificates. */

    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char*)GLITCHEDHTTPS_CA_CERTS, sizeof(GLITCHEDHTTPS_CA_CERTS));
    if (ret < 0)
    {
        char msg[128];
        sprintf(msg, "HTTPS request failed: \"mbedtls_x509_crt_parse\" returned -0x%x", -ret);
        _glitchedhttps_log_error(msg, __func__);
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
        _glitchedhttps_log_error(msg, __func__);
        goto exit;
    }

    /*  Set up the SSL/TLS structure. */

    ret = mbedtls_ssl_config_defaults(&ssl_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
    {
        char msg[128];
        sprintf(msg, "HTTPS request failed: \"mbedtls_ssl_config_defaults\" returned %d", ret);
        _glitchedhttps_log_error(msg, __func__);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&ssl_config, ssl_verification_optional ? MBEDTLS_SSL_VERIFY_OPTIONAL : MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&ssl_config, &cacert, NULL);
    mbedtls_ssl_conf_rng(&ssl_config, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&ssl_config, &_glitchedhttps_debug, stdout);

    ret = mbedtls_ssl_setup(&ssl_context, &ssl_config);
    if (ret != 0)
    {
        char msg[128];
        sprintf(msg, "HTTPS request failed: \"mbedtls_ssl_setup\" returned %d", ret);
        _glitchedhttps_log_error(msg, __func__);
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(&ssl_context, server_name);
    if (ret != 0)
    {
        char msg[128];
        sprintf(msg, "HTTPS request failed: \"mbedtls_ssl_set_hostname\" returned %d", ret);
        _glitchedhttps_log_error(msg, __func__);
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
            _glitchedhttps_log_error(msg, __func__);
            goto exit;
        }
    }

    /* Verify the server's X.509 certificate. */

    flags = mbedtls_ssl_get_verify_result(&ssl_context);
    if (flags != 0)
    {
        char verification_buffer[1024];
        mbedtls_x509_crt_verify_info(verification_buffer, sizeof(verification_buffer), "  ! ", flags);
        _glitchedhttps_log_error(verification_buffer, __func__);
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
            _glitchedhttps_log_error(msg, __func__);
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
            _glitchedhttps_log_error(msg, __func__);
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
        _glitchedhttps_log_error("HTTP response string empty!", __func__);
        goto exit;
    }

    out = _glitchedhttps_parse_response_string(&response_string);

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
        _glitchedhttps_log_error(msg, __func__);
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
static glitchedhttps_response* _glitchedhttps_http_request(const char* server_name, const int server_port, const char* request, const size_t buffer_size)
{
    if (server_name == NULL || request == NULL || server_port <= 0)
    {
        _glitchedhttps_log_error("INVALID HTTP parameters passed into \"_glitchedhttps_http_request\". Returning NULL...", __func__);
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
//    _glitchedhttps_log_error("\"gethostbyname\" failed!", __func__);
//    goto exit;
//}
//
// server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
// if (server_fd < 0)
//{
//    char msg[128];
//    sprintf(msg, "HTTP request failed: \"socket\" returned %d", server_fd);
//    _glitchedhttps_log_error(msg, __func__);
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
//    _glitchedhttps_log_error(msg, __func__);
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
//        _glitchedhttps_log_error(msg, __func__);
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
//        _glitchedhttps_log_error(msg, __func__);
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
 * Not good...
 */
#define GLITCHEDHTTPS_OVERFLOW 600

/**
 * Submits a given HTTP request and returns the server response. <p>
 * This allocates memory, so don't forget to {@link #glitchedhttps_response_free()} the returned glitchedhttps_response instance after usage!!
 * @param request The glitchedhttps_request instance containing the request parameters and data (e.g. url, body, etc...).
 * @param out The output glitchedhttps_response into which to write the response's data and headers. Must be fresh, allocated and ready!
 * @return The (freshly allocated) glitchedhttps_response instance containing the response headers, status code, etc... if the request was submitted successfully; <code>NULL</code> if the request couldn't even be submitted (e.g. invalid URL/server not found/no internet/whatever..).
 */
int glitchedhttps_submit(const glitchedhttps_request* request, glitchedhttps_response* out)
{
    if (request == NULL)
    {
        _glitchedhttps_log_error("Request parameter NULL!", __func__);
        return GLITCHEDHTTPS_NULL_ARG;
    }

    if (out == NULL)
    {
        _glitchedhttps_log_error("Out parameter NULL; nothing to write the HTTP request's response into!", __func__);
        return GLITCHEDHTTPS_NULL_ARG;
    }

    if (request->url == NULL)
    {
        _glitchedhttps_log_error("URL parameter NULL!", __func__);
        return GLITCHEDHTTPS_NULL_ARG;
    }

    const bool https = glitchedhttps_is_https(request->url);
    const char* server_host_ptr = https ? request->url + 8 : glitchedhttps_is_http(request->url) ? request->url + 7 : NULL;

    if (server_host_ptr == NULL)
    {
        _glitchedhttps_log_error("Missing or invalid protocol in passed URL: needs \"http://\" or \"https://\"", __func__);
        return GLITCHEDHTTPS_INVALID_ARG;
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
                snprintf(msg, sizeof(msg), "Invalid port number \"%d\"", server_port);
                _glitchedhttps_log_error(msg, __func__);
                return GLITCHEDHTTPS_INVALID_PORT_NUMBER;
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
    method[sizeof(method) - 1] = '\0';

    if (!glitchedhttps_method_to_string(request->method, method, sizeof(method)))
    {
        _glitchedhttps_log_error("HTTP request submission rejected due to invalid HTTP method name.", __func__);
        return GLITCHEDHTTPS_INVALID_HTTP_METHOD_NAME;
    }

    chillbuff request_string;

    if (chillbuff_init(&request_string, 1024, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE) != CHILLBUFF_SUCCESS)
    {
        _glitchedhttps_log_error("Chillbuff init failed: can't proceed without a proper request string builder... Perhaps go check out the chillbuff error logs!", __func__);
        return GLITCHEDHTTPS_EXTERNAL_ERROR;
    }

    const char crlf[] = "\r\n";
    const size_t crlf_length = strlen(crlf);

    const char whitespace[] = " ";
    const size_t whitespace_length = strlen(whitespace);

    const char header_separator[] = ": ";
    const size_t header_separator_length = strlen(header_separator);

    const char http_version[] = "HTTP/1.1";
    const size_t http_version_length = strlen(http_version);

    const char host[] = "Host: ";
    const size_t host_length = strlen(host);

    const char content_type[] = "Content-Type: ";
    const size_t content_type_length = strlen(content_type);

    const char content_length[] = "Content-Length: ";
    const size_t content_length_strlen = strlen(content_length);

    const char content_encoding[] = "Content-Encoding: ";
    const size_t content_encoding_length = strlen(content_encoding);

    const char connection[] = "Connection: Close";
    const size_t connection_length = strlen(connection);

    chillbuff_push_back(&request_string, method, strlen(method));
    chillbuff_push_back(&request_string, whitespace, whitespace_length);
    chillbuff_push_back(&request_string, path, strlen(path));
    chillbuff_push_back(&request_string, whitespace, whitespace_length);
    chillbuff_push_back(&request_string, http_version, http_version_length);
    chillbuff_push_back(&request_string, crlf, crlf_length);
    chillbuff_push_back(&request_string, host, host_length);
    chillbuff_push_back(&request_string, server_host, strlen(server_host));
    chillbuff_push_back(&request_string, crlf, crlf_length);
    chillbuff_push_back(&request_string, connection, connection_length);
    chillbuff_push_back(&request_string, crlf, crlf_length);

    for (size_t i = 0; i < request->additional_headers_count; i++)
    {
        glitchedhttps_header header = request->additional_headers[i];

        chillbuff_push_back(&request_string, header.type, strlen(header.type));
        chillbuff_push_back(&request_string, header_separator, header_separator_length);
        chillbuff_push_back(&request_string, header.value, strlen(header.value));
        chillbuff_push_back(&request_string, crlf, crlf_length);
    }

    if (request->content != NULL && request->content_type != NULL && request->content_length > 0)
    {
        const size_t content_strlen = strlen(request->content);
        if (content_strlen > 0)
        {
            chillbuff_push_back(&request_string, content_type, content_type_length);
            chillbuff_push_back(&request_string, request->content_type, strlen(request->content_type));
            chillbuff_push_back(&request_string, crlf, crlf_length);

            if (request->content_encoding != NULL)
            {
                const size_t content_encoding_value_length = strlen(request->content_encoding);
                if (content_encoding_value_length > 0)
                {
                    chillbuff_push_back(&request_string, content_encoding, content_encoding_length);
                    chillbuff_push_back(&request_string, request->content_encoding, content_encoding_value_length);
                    chillbuff_push_back(&request_string, crlf, crlf_length);
                }
            }

            chillbuff_push_back(&request_string, content_length, content_length_strlen);
            char content_length_value[64];
            const int content_length_value_digits = snprintf(content_length_value, sizeof(content_length_value), "%zu", request->content_length);
            chillbuff_push_back(&request_string, content_length_value, content_length_value_digits);

            chillbuff_push_back(&request_string, crlf, crlf_length);
            chillbuff_push_back(&request_string, crlf, crlf_length);
            chillbuff_push_back(&request_string, request->content, strlen(request->content));
            chillbuff_push_back(&request_string, crlf, crlf_length);
        }
    }

    chillbuff_push_back(&request_string, crlf, crlf_length);

    glitchedhttps_response* _out = https ? _glitchedhttps_https_request(server_host, server_port, request_string.array, request->buffer_size, request->ssl_verification_optional) : _glitchedhttps_http_request(server_host, server_port, request_string.array, request->buffer_size);
    chillbuff_free(&request_string);
    // return GLITCHEDHTTPS_SUCCESS;
    return _out; // TODO: return success code instead once refactoring is done!
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_H
