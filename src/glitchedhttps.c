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

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef __MINGW32__
#include <wspiapi.h>
#endif
#else
#define closesocket close
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#pragma comment(lib, "ws2_32.lib")
void clear_win_sock()
{
#if defined WIN32
    WSACleanup();
#endif
}

#include <time.h>
#include <ctype.h>
#include <stdio.h>

#include "chillbuff.h"

#include <mbedtls/net.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/platform.h>
#include <mbedtls/error.h>

#include "glitchedhttps.h"
#include "glitchedhttps_cacerts.h"
#include "glitchedhttps_strutil.h"
#include "glitchedhttps_debug.h"
#include "glitchedhttps_guid.h"

static const char header_delimiter[] = "\r\n";
static const size_t header_delimiter_length = 2;

static const char content_delimiter[] = "\r\n\r\n";
static const size_t content_delimiter_length = 4;

#define GLITCHEDHTTPS_DEFAULT_CHUNK_BUFFERSIZE 1024
#define GLITCHEDHTTPS_MAX(x, y) (((x) > (y)) ? (x) : (y))

/** @private */
static int parse_response_string(const chillbuff* response_string, struct glitchedhttps_response** out)
{
    if (response_string == NULL)
    {
        glitchedhttps_log_error("HTTP response parse error: \"response_string\" argument NULL; nothing to parse!", __func__);
        return GLITCHEDHTTPS_RESPONSE_PARSE_ERROR;
    }

    /* Allocate the output http response struct and set pointers to default value "NULL".
     * The consumer of this returned value should not forget to call  on this! */
    struct glitchedhttps_response* response = malloc(sizeof(struct glitchedhttps_response));
    if (response == NULL)
    {
        glitchedhttps_log_error("OUT OF MEMORY!", __func__);
        return GLITCHEDHTTPS_OUT_OF_MEM;
    }

    response->raw = NULL;
    response->date = NULL;
    response->server = NULL;
    response->headers = NULL;
    response->content = NULL;
    response->content_type = NULL;
    response->content_encoding = NULL;
    response->content_length = 0;
    response->headers_count = 0;
    response->status_code = -1;

    response->raw = malloc((response_string->length + 1) * response_string->element_size);
    if (response->raw == NULL)
    {
        glitchedhttps_response_free(response);
        glitchedhttps_log_error("OUT OF MEMORY!", __func__);
        return GLITCHEDHTTPS_OUT_OF_MEM;
    }

    /* First of all, copy the whole, raw response string into the output. */
    memcpy(response->raw, response_string->array, response_string->length);
    response->raw[response_string->length] = '\0';

    /* Next comes the tedious parsing. */

    char* current = response_string->array;
    char* next = strstr(current, header_delimiter);

    int parsed_status = 0, parsed_server = 0, parsed_date = 0, parsed_content_type = 0, parsed_content_encoding = 0, parsed_content_length = 0, parsed_chunked_transfer = 0;

    chillbuff header_builder;
    if (chillbuff_init(&header_builder, 16, sizeof(struct glitchedhttps_header), CHILLBUFF_GROW_DUPLICATIVE) != CHILLBUFF_SUCCESS)
    {
        glitchedhttps_log_error("Chillbuff init failed: can't proceed without a proper request string builder... Perhaps go check out the chillbuff error logs!", __func__);
        return GLITCHEDHTTPS_CHILLBUFF_ERROR;
    }

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
                response->status_code = strtol(n, NULL, 10);
            }
            parsed_status = 1;
        }
        else if (!parsed_server && glitchedhttps_strncmpic(current, "Server: ", 8) == 0)
        {
            const size_t out_length = current_length - 8;
            response->server = malloc((out_length + 1) * sizeof(char));
            if (response->server == NULL)
            {
                goto out_of_mem;
            }
            memcpy(response->server, current + 8, out_length);
            response->server[out_length] = '\0';
            chillbuff_push_back(&header_builder, glitchedhttps_header_init(current, 6, response->server, out_length), 1);
            parsed_server = 1;
        }
        else if (!parsed_date && glitchedhttps_strncmpic(current, "Date: ", 6) == 0)
        {
            const size_t out_length = current_length - 6;
            response->date = malloc((out_length + 1) * sizeof(char));
            if (response->date == NULL)
            {
                goto out_of_mem;
            }
            memcpy(response->date, current + 6, out_length);
            response->date[out_length] = '\0';
            chillbuff_push_back(&header_builder, glitchedhttps_header_init(current, 4, response->date, out_length), 1);
            parsed_date = 1;
        }
        else if (!parsed_content_type && glitchedhttps_strncmpic(current, "Content-Type: ", 14) == 0)
        {
            const size_t out_length = current_length - 14;
            response->content_type = malloc((out_length + 1) * sizeof(char));
            if (response->content_type == NULL)
            {
                goto out_of_mem;
            }
            memcpy(response->content_type, current + 14, out_length);
            response->content_type[out_length] = '\0';
            chillbuff_push_back(&header_builder, glitchedhttps_header_init(current, 12, response->content_type, out_length), 1);
            parsed_content_type = 1;
        }
        else if (!parsed_content_encoding && glitchedhttps_strncmpic(current, "Content-Encoding: ", 18) == 0)
        {
            const size_t out_length = current_length - 18;
            response->content_encoding = malloc((out_length + 1) * sizeof(char));
            if (response->content_encoding == NULL)
            {
                goto out_of_mem;
            }
            memcpy(response->content_encoding, current + 18, out_length);
            response->content_encoding[out_length] = '\0';
            chillbuff_push_back(&header_builder, glitchedhttps_header_init(current, 16, response->content_encoding, out_length), 1);
            parsed_content_encoding = 1;
        }
        else if (!parsed_content_length && glitchedhttps_strncmpic(current, "Content-Length: ", 16) == 0)
        {
            char n[64];
            memset(n, '\0', sizeof(n));
            const char* c = memchr(current, ' ', current_length);
            if (c != NULL)
            {
                memcpy(n, c + 1, current_length - 1);
                response->content_length = strtol(n, NULL, 10);
                snprintf(n, sizeof(n), "%zu", response->content_length);
                chillbuff_push_back(&header_builder, glitchedhttps_header_init(current, 14, n, strlen(n)), 1);
            }
            parsed_content_length = 1;
        }
        else if (glitchedhttps_strncmpic(current, "Transfer-Encoding: chunked", 26) == 0) // Allow HTTP/1.1's chunked transfer encoding.
        {
            chillbuff_push_back(&header_builder, glitchedhttps_header_init("Transfer-Encoding", 17, "chunked", 7), 1);
            parsed_chunked_transfer = 1;
        }
        else if (current != response_string->array && strncmp(current - header_delimiter_length, content_delimiter, content_delimiter_length) == 0) // content body found
        {
            char* content = (current - header_delimiter_length) + content_delimiter_length;
            size_t content_length = parsed_chunked_transfer ? GLITCHEDHTTPS_DEFAULT_CHUNK_BUFFERSIZE : response->content_length;
            if (content_length > 0)
            {
                if (parsed_chunked_transfer)
                {
                    chillbuff content_buffer;
                    int r = chillbuff_init(&content_buffer, content_length, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE);
                    if (r != CHILLBUFF_SUCCESS)
                    {
                        goto out_of_mem;
                    }

                    size_t chunksize;
                    while ((chunksize = strtol(content, NULL, 16)) != 0)
                    {
                        content = strstr(content, header_delimiter);
                        if (content == NULL)
                        {
                            break;
                        }
                        content += header_delimiter_length;
                        chillbuff_push_back(&content_buffer, content, chunksize);
                        content += chunksize + header_delimiter_length;
                    }

                    response->content = malloc(content_buffer.length + 1);
                    if (response->content == NULL)
                    {
                        goto out_of_mem;
                    }
                    memcpy(response->content, content_buffer.array, content_buffer.length);
                    response->content[content_buffer.length] = '\0';
                    chillbuff_clear(&content_buffer);
                }
                else
                {
                    response->content = malloc(content_length + 1);
                    if (response->content == NULL)
                    {
                        goto out_of_mem;
                    }
                    memcpy(response->content, content, content_length);
                    response->content[content_length] = '\0';
                }
            }
            else
            {
                response->content = NULL;
                response->content_length = 0;
            }
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
        current = next + header_delimiter_length;
        next = strstr(current, header_delimiter);
    }

    response->headers = malloc(sizeof(struct glitchedhttps_header) * header_builder.length);
    if (response->headers == NULL)
    {
        goto out_of_mem;
    }

    /* Copy the response headers into the output instance. */
    response->headers_count = header_builder.length;
    for (size_t i = 0; i < header_builder.length; i++)
    {
        const struct glitchedhttps_header h = ((struct glitchedhttps_header*)header_builder.array)[i];
        response->headers[i] = *glitchedhttps_header_init(h.type, strlen(h.type), h.value, strlen(h.value));
    }

    *out = response;
    chillbuff_free(&header_builder);
    return GLITCHEDHTTPS_SUCCESS;

out_of_mem:
    glitchedhttps_log_error("OUT OF MEMORY!", __func__);
    glitchedhttps_response_free(response);
    chillbuff_free(&header_builder);
    return GLITCHEDHTTPS_OUT_OF_MEM;
}

/** @private */
static int https_request(const char* server_name, const int server_port, const char* request, const size_t buffer_size, const int ssl_verification_optional, struct glitchedhttps_response** out)
{
    if (server_name == NULL || request == NULL || server_port <= 0)
    {
        glitchedhttps_log_error("INVALID HTTPS parameters passed into \"https_request\". Returning NULL...", __func__);
        return GLITCHEDHTTPS_INVALID_ARG;
    }

    chillbuff response_string;

    if (chillbuff_init(&response_string, 1024, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE) != CHILLBUFF_SUCCESS)
    {
        glitchedhttps_log_error("Chillbuff init failed: can't proceed without a proper request string builder... Perhaps go check out the chillbuff error logs!", __func__);
        return GLITCHEDHTTPS_CHILLBUFF_ERROR;
    }

    uint32_t flags;
    int ret = 1, exit_code = -1;
    int mbedtls_exit_code = MBEDTLS_EXIT_FAILURE;

    char error_msg[256];
    memset(error_msg, '\0', sizeof error_msg);

    unsigned char buffer_stack[8192];
    unsigned char* buffer_heap = NULL;
    if (buffer_size > sizeof(buffer_stack))
    {
        buffer_heap = malloc(buffer_size * sizeof(unsigned char));
        if (buffer_heap == NULL)
        {
            glitchedhttps_log_error("Buffer size too big; malloc failed! Using default (stack-allocated) 8192-Bytes buffer instead...", __func__);
        }
    }

    unsigned char* buffer = buffer_heap != NULL ? buffer_heap : buffer_stack;

    time_t t;
    srand((unsigned)time(&t));

    struct glitchedhttps_guid guid = glitchedhttps_new_guid(rand() & 1, rand() & 1);

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
        snprintf(error_msg, sizeof(error_msg), "HTTPS request failed: \"mbedtls_ctr_drbg_seed\" returned %d", ret);
        glitchedhttps_log_error(error_msg, __func__);
        exit_code = GLITCHEDHTTPS_EXTERNAL_ERROR;
        goto exit;
    }

    /* Load the CA root certificates. */

    const unsigned char* ca = (const unsigned char*)glitchedhttps_get_ca_certs();
    const size_t calen = glitchedhttps_get_ca_certs_length();

    ret = mbedtls_x509_crt_parse(&cacert, ca, calen);
    if (ret < 0)
    {
        snprintf(error_msg, sizeof(error_msg), "HTTPS request failed: \"mbedtls_x509_crt_parse\" returned -0x%x", -ret);
        glitchedhttps_log_error(error_msg, __func__);
        exit_code = GLITCHEDHTTPS_EXTERNAL_ERROR;
        goto exit;
    }

    /* Open the connection to the specified host. */

    char port[8];
    memset(port, '\0', sizeof(port));
    snprintf(port, sizeof(port), "%d", server_port);

    ret = mbedtls_net_connect(&net_context, server_name, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        snprintf(error_msg, sizeof(error_msg), "HTTPS request failed: \"mbedtls_net_connect\" returned %d", ret);
        glitchedhttps_log_error(error_msg, __func__);
        exit_code = GLITCHEDHTTPS_EXTERNAL_ERROR;
        goto exit;
    }

    /*  Set up the SSL/TLS structure. */

    ret = mbedtls_ssl_config_defaults(&ssl_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
    {
        snprintf(error_msg, sizeof(error_msg), "HTTPS request failed: \"mbedtls_ssl_config_defaults\" returned %d", ret);
        glitchedhttps_log_error(error_msg, __func__);
        exit_code = GLITCHEDHTTPS_EXTERNAL_ERROR;
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&ssl_config, ssl_verification_optional ? MBEDTLS_SSL_VERIFY_OPTIONAL : MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&ssl_config, &cacert, NULL);
    mbedtls_ssl_conf_rng(&ssl_config, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&ssl_config, &glitchedhttps_debug, stdout);

    ret = mbedtls_ssl_setup(&ssl_context, &ssl_config);
    if (ret != 0)
    {
        snprintf(error_msg, sizeof(error_msg), "HTTPS request failed: \"mbedtls_ssl_setup\" returned %d", ret);
        glitchedhttps_log_error(error_msg, __func__);
        exit_code = GLITCHEDHTTPS_EXTERNAL_ERROR;
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(&ssl_context, server_name);
    if (ret != 0)
    {
        snprintf(error_msg, sizeof(error_msg), "HTTPS request failed: \"mbedtls_ssl_set_hostname\" returned %d", ret);
        glitchedhttps_log_error(error_msg, __func__);
        exit_code = GLITCHEDHTTPS_EXTERNAL_ERROR;
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl_context, &net_context, mbedtls_net_send, mbedtls_net_recv, NULL);

    /* SSL Handshake. */

    while ((ret = mbedtls_ssl_handshake(&ssl_context)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            snprintf(error_msg, sizeof(error_msg), "HTTPS request failed: \"mbedtls_ssl_handshake\" returned -0x%x", -ret);
            glitchedhttps_log_error(error_msg, __func__);
            exit_code = GLITCHEDHTTPS_EXTERNAL_ERROR;
            goto exit;
        }
    }

    /* Verify the server's X.509 certificate. */

    flags = mbedtls_ssl_get_verify_result(&ssl_context);
    if (flags != 0)
    {
        char verification_buffer[1024];
        mbedtls_x509_crt_verify_info(verification_buffer, sizeof(verification_buffer), "  ! ", flags);
        glitchedhttps_log_error(verification_buffer, __func__);
        exit_code = GLITCHEDHTTPS_EXTERNAL_ERROR;
        goto exit;
    }

    /* Write the request string.*/

    while ((ret = mbedtls_ssl_write(&ssl_context, (const unsigned char*)request, strlen(request))) <= 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            snprintf(error_msg, sizeof(error_msg), "HTTPS request failed: \"mbedtls_ssl_write\" returned %d", ret);
            glitchedhttps_log_error(error_msg, __func__);
            exit_code = GLITCHEDHTTPS_EXTERNAL_ERROR;
            goto exit;
        }
    }

    /* Read the HTTP response. */

    for (;;)
    {
        const size_t length = (buffer_heap != NULL ? (buffer_size * sizeof(unsigned char)) : sizeof(buffer_stack));
        memset(buffer, '\0', length);
        ret = mbedtls_ssl_read(&ssl_context, buffer, length - 1);

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
            snprintf(error_msg, sizeof(error_msg), "HTTPS request failed: \"mbedtls_ssl_read\" returned %d", ret);
            glitchedhttps_log_error(error_msg, __func__);
            exit_code = GLITCHEDHTTPS_EXTERNAL_ERROR;
            goto exit;
        }

        if (ret == 0)
        {
            /* EOF; ready to close the connection. */
            break;
        }

        chillbuff_push_back(&response_string, buffer, ret);
    }

    if (response_string.length == 0)
    {
        glitchedhttps_log_error("HTTP response string empty!", __func__);
        exit_code = GLITCHEDHTTPS_EXTERNAL_ERROR;
        goto exit;
    }

    exit_code = parse_response_string(&response_string, out);
    mbedtls_ssl_close_notify(&ssl_context);
    mbedtls_exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#ifdef MBEDTLS_ERROR_C
    if (mbedtls_exit_code != MBEDTLS_EXIT_SUCCESS)
    {
        char error_buf[2048];
        memset(error_buf, '\0', sizeof(error_buf));
        int f = snprintf(error_buf, sizeof(error_buf), "HTTPS request unsuccessful! Last error was: %d - ", ret);
        mbedtls_strerror(ret, error_buf + f, sizeof(error_buf) - f - 1);
        glitchedhttps_log_error(error_buf, __func__);
    }
#endif

    free(buffer_heap);
    mbedtls_net_free(&net_context);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl_context);
    mbedtls_ssl_config_free(&ssl_config);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    chillbuff_free(&response_string);

    return exit_code;
}

/** @private */
static int http_request(const char* server_name, const int server_port, const char* request, const size_t buffer_size, struct glitchedhttps_response** out)
{
    int exit_code, ret;

    if (server_name == NULL || request == NULL || server_port <= 0)
    {
        glitchedhttps_log_error("INVALID HTTP parameters passed into \"http_request()\".", __func__);
        return GLITCHEDHTTPS_INVALID_ARG;
    }

#if defined WIN32
    WSADATA wsaData;
    ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0)
    {
        glitchedhttps_log_error("Error at \"WSAStartup\".", __func__);
        return GLITCHEDHTTPS_EXTERNAL_ERROR;
    }
#endif

    chillbuff response_string;

    if (chillbuff_init(&response_string, 1024, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE) != CHILLBUFF_SUCCESS)
    {
        glitchedhttps_log_error("Chillbuff init failed: can't proceed without a proper request string builder... Perhaps go check out the chillbuff error logs!", __func__);
        return GLITCHEDHTTPS_CHILLBUFF_ERROR;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port[8];
    memset(port, '\0', sizeof(port));
    snprintf(port, sizeof(port), "%d", server_port);

    struct addrinfo* res = NULL;
    ret = getaddrinfo(server_name, port, &hints, &res);
    if (ret != 0 || res == NULL)
    {
        char msg[128];
        snprintf(msg, sizeof(msg), "\"getaddrinfo\" failed with error code: %d", ret);
        glitchedhttps_log_error(msg, __func__);
        chillbuff_free(&response_string);
        if (res != NULL)
            freeaddrinfo(res);
        return GLITCHEDHTTPS_HTTP_GETADDRINFO_FAILED;
    }

    char buffer_stack[8192];
    char* buffer_heap = NULL;
    if (buffer_size > sizeof(buffer_stack))
    {
        buffer_heap = malloc(buffer_size * sizeof(char));
        if (buffer_heap == NULL)
        {
            glitchedhttps_log_error("Buffer size too big; malloc failed! Using default (stack-allocated) 8192-Bytes buffer instead...", __func__);
        }
    }

    char* buffer = buffer_heap != NULL ? buffer_heap : buffer_stack;

    int sockfd = (int)socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (connect(sockfd, res->ai_addr, (int)res->ai_addrlen) != 0)
    {
        glitchedhttps_log_error("Connection to server failed!", __func__);
        exit_code = GLITCHEDHTTPS_CONNECTION_TO_SERVER_FAILED;
        goto exit;
    }

    if (send(sockfd, request, (int)strlen(request), 0) < 0)
    {
        glitchedhttps_log_error("Connection to server was successful but HTTP Request could not be transmitted!", __func__);
        exit_code = GLITCHEDHTTPS_HTTP_REQUEST_TRANSMISSION_FAILED;
        goto exit;
    }

    for (;;)
    {
        const int length = (int)(buffer_heap != NULL ? (buffer_size * sizeof(char)) : sizeof(buffer_stack));
        memset(buffer, '\0', length);
        ret = recv(sockfd, buffer, length - 1, 0);

        if (ret < 0)
        {
            char msg[128];
            snprintf(msg, sizeof(msg), "HTTP request failed: \"recv()\" returned %d", ret);
            glitchedhttps_log_error(msg, __func__);
            exit_code = GLITCHEDHTTPS_EXTERNAL_ERROR;
            goto exit;
        }

        if (ret == 0)
        {
            /* EOF; ready to close the connection. */
            break;
        }

        chillbuff_push_back(&response_string, buffer, ret);
    }

    if (response_string.length == 0)
    {
        glitchedhttps_log_error("HTTP response string empty!", __func__);
        exit_code = GLITCHEDHTTPS_EMPTY_RESPONSE;
        goto exit;
    }

    exit_code = parse_response_string(&response_string, out);

exit:
    if (res != NULL)
    {
        freeaddrinfo(res);
    }
    free(buffer_heap);
    chillbuff_free(&response_string);
    closesocket(sockfd);
    clear_win_sock();
    return exit_code;
}

int glitchedhttps_submit(const struct glitchedhttps_request* request, struct glitchedhttps_response** out)
{
    if (request == NULL)
    {
        glitchedhttps_log_error("Request parameter NULL!", __func__);
        return GLITCHEDHTTPS_NULL_ARG;
    }

    if (out == NULL)
    {
        glitchedhttps_log_error("Out parameter NULL; nothing to write the HTTP request's response into!", __func__);
        return GLITCHEDHTTPS_NULL_ARG;
    }

    if (request->url == NULL)
    {
        glitchedhttps_log_error("URL parameter NULL!", __func__);
        return GLITCHEDHTTPS_NULL_ARG;
    }

    if (request->url_length < 7 && strlen(request->url) < 7)
    {
        glitchedhttps_log_error("Invalid URL!", __func__);
        return GLITCHEDHTTPS_INVALID_ARG;
    }

    const int https = glitchedhttps_is_https(request->url);
    const char* server_host_ptr = https ? request->url + 8 : glitchedhttps_is_http(request->url) ? request->url + 7 : NULL;

    if (server_host_ptr == NULL)
    {
        glitchedhttps_log_error("Missing or invalid protocol in passed URL: needs to be \"http://\" or \"https://\"", __func__);
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
            server_port = strtol(custom_port + 1, NULL, 10);
            if (server_port <= 0 || server_port >= 65536)
            {
                char msg[128];
                snprintf(msg, sizeof(msg), "Invalid port number \"%d\"", server_port);
                glitchedhttps_log_error(msg, __func__);
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
        glitchedhttps_log_error("HTTP request submission rejected due to invalid HTTP method name.", __func__);
        return GLITCHEDHTTPS_INVALID_HTTP_METHOD_NAME;
    }

    chillbuff request_string;

    if (chillbuff_init(&request_string, 1024, sizeof(char), CHILLBUFF_GROW_DUPLICATIVE) != CHILLBUFF_SUCCESS)
    {
        glitchedhttps_log_error("Chillbuff init failed: can't proceed without a proper request string builder... Perhaps go check out the chillbuff error logs!", __func__);
        return GLITCHEDHTTPS_CHILLBUFF_ERROR;
    }

    const char crlf[] = "\r\n";
    const size_t crlf_length = strlen(crlf);

    const char whitespace[] = " ";
    const size_t whitespace_length = 1;

    const char header_separator[] = ": ";
    const size_t header_separator_length = 2;

    const char http_version[] = "HTTP/1.1";
    const size_t http_version_length = 8;

    const char host[] = "Host: ";
    const size_t host_length = 6;

    const char content_type[] = "Content-Type: ";
    const size_t content_type_length = 14;

    const char content_length[] = "Content-Length: ";
    const size_t content_length_strlen = 16;

    const char content_encoding[] = "Content-Encoding: ";
    const size_t content_encoding_length = 18;

    const char connection[] = "Connection: Close";
    const size_t connection_length = 17;

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

    for (size_t i = 0; i < request->additional_headers_count; ++i)
    {
        struct glitchedhttps_header header = request->additional_headers[i];

        chillbuff_push_back(&request_string, header.type, strlen(header.type));
        chillbuff_push_back(&request_string, header_separator, header_separator_length);
        chillbuff_push_back(&request_string, header.value, strlen(header.value));
        chillbuff_push_back(&request_string, crlf, crlf_length);
    }

    if (request->content != NULL && request->content_type != NULL && request->content_length > 0)
    {
        if (strlen(request->content) > 0)
        {
            chillbuff_push_back(&request_string, content_type, content_type_length);
            chillbuff_push_back(&request_string, request->content_type, request->content_type_length ? request->content_type_length : strlen(request->content_type));
            chillbuff_push_back(&request_string, crlf, crlf_length);

            if (request->content_encoding != NULL)
            {
                const size_t content_encoding_value_length = request->content_encoding_length ? request->content_encoding_length : strlen(request->content_encoding);
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

    int result = https ? https_request(server_host, server_port, request_string.array, request->buffer_size, request->ssl_verification_optional, out) : http_request(server_host, server_port, request_string.array, request->buffer_size, out);
    chillbuff_free(&request_string);
    return result;
}

#undef closesocket
#undef GLITCHEDHTTPS_MAX
#undef GLITCHEDHTTPS_DEFAULT_CHUNK_BUFFERSIZE

#ifdef __cplusplus
} // extern "C"
#endif
