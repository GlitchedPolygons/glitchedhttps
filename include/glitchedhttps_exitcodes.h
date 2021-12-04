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
 *  @file glitchedhttps_exitcodes.h
 *  @brief Exit codes returned by the various glitchedhttps functions.
 */

#ifndef GLITCHEDHTTPS_EXITCODES_H
#define GLITCHEDHTTPS_EXITCODES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returned from a glitchedhttps function when everything went as expected.
 */
#define GLITCHEDHTTPS_SUCCESS 0

/**
 * Returned when trying to submit a request without having initialized GlitchedHTTPS with the glitchedhttps_init() function first. <p>
 * Never forget to glitchedhttps_free() once you're done using GlitchedHTTPS to release the resources and prevent memory leaks!
 */
#define GLITCHEDHTTPS_UNINITIALIZED 10

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
 * When the error is not due to glitchedhttps but the underlying chillbuff instance
 * (e.g. if the chillbuff init function fails for some reason (e.g. out of memory/failure to reallocate) and the http request function can't proceed without a stringbuilder).
 */
#define GLITCHEDHTTPS_CHILLBUFF_ERROR 600

/**
 * Returned if the HTTP response string couldn't be parsed.
 */
#define GLITCHEDHTTPS_RESPONSE_PARSE_ERROR 700

/**
 * When something fails that has nothing to do with glitchedhttps, like
 * for example if something failed inside an MbedTLS function; in that case,
 * check the logs (if you provided an error callback via the {@link #glitchedhttps_set_error_callback()} function).
 */
#define GLITCHEDHTTPS_EXTERNAL_ERROR 800

/**
 * Not good...
 */
#define GLITCHEDHTTPS_OVERFLOW 900

/**
 * Returned by a plain HTTP request if connection to the specified server couldn't be established.
 */
#define GLITCHEDHTTPS_CONNECTION_TO_SERVER_FAILED 1000

/**
 * Returned by a plain HTTP request if connection to the specified server was successful
 * but the request couldn't be transmitted to the server.
 */
#define GLITCHEDHTTPS_HTTP_REQUEST_TRANSMISSION_FAILED 1100

/**
 * Returned if the plain http:// request failed due to a <code>getaddrinfo()</code> failure.
 */
#define GLITCHEDHTTPS_HTTP_GETADDRINFO_FAILED 1200

/**
 * If the returned HTTP response string is empty.
 */
#define GLITCHEDHTTPS_EMPTY_RESPONSE 1300

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_EXITCODES_H
