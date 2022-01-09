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
 *  @file glitchedhttps.h
 *  @brief Simple, lightweight and straight-forward way of doing HTTP(S) requests in C with the help of ARM's open-source MbedTLS library.
 *  @see https://github.com/GlitchedPolygons/glitchedhttps
 */

/**
 * @mainpage Glitched HTTPS
 * @section intro Introduction
 * Glitched HTTPS is a simple, lightweight and straight-forward way of doing HTTP(S) requests in C with the help of ARM's open-source MbedTLS library.
 * @section deps Dependencies
 * * [CMake >3.12](https://cmake.org/download/)
 * * [ARM MbedTLS](https://github.com/ARMmbed/mbedtls)
 * @section install Installation
 * See the git repository's [README.md](https://github.com/GlitchedPolygons/glitchedhttps) for instructions on how to get started with this.
 * @section usage Usage
 * Inside the git repo's [examples/](https://github.com/GlitchedPolygons/glitchedhttps/tree/master/examples) folder you can find many examples on how to make requests using Glitched HTTPS. <p>
 * Furthermore, here is a list of the most important types used within Glitched HTTPS:
 * * {@link #glitchedhttps_header} - This is a HTTP header (the ones you find in an HTTP request or response).
 * * {@link #glitchedhttps_method} - An enumeration that specifies the HTTP method to use for a request (e.g. "GET", "POST", ...).
 * * {@link #glitchedhttps_request} - Struct containing all the parameters necessary for an HTTP request (HTTP Method, Body, URL, which **MUST** contain either the scheme [`http://`](#) or [`https://`](#), etc...).
 * * ➥ You can allocate this on the stack right before submitting the request if you want, just as seen as in the [`PUT` request example](https://github.com/GlitchedPolygons/glitchedhttps/blob/master/examples/put/main.c).
 * * {@link #glitchedhttps_response} - HTTP Response data. This struct contains the mapped status code, response content (body), and all the headers..
 * * ➥ Must be freed using the {@link #glitchedhttps_response_free()} function!
 * <p> Also: check out the @ref glitchedhttps_exitcodes.h header file to find out what each of the Glitched HTTPS functions' exit codes means!
 */

#ifndef GLITCHEDHTTPS_H
#define GLITCHEDHTTPS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "glitchedhttps_api.h"
#include "glitchedhttps_request.h"
#include "glitchedhttps_response.h"
#include "glitchedhttps_exitcodes.h"

/**
 * Current version of the used GlitchedHTTPS library.
 */
#define GLITCHEDHTTPS_VERSION 101

/**
 * Current version of the used GlitchedHTTPS library (nicely-formatted string).
 */
#define GLITCHEDHTTPS_VERSION_STR "1.0.1"

#ifndef GLITCHEDHTTPS_STACK_BUFFERSIZE
/**
 * The maximum size in bytes that a temporary buffer may allocate on the stack before requiring a \c malloc
 */
#define GLITCHEDHTTPS_STACK_BUFFERSIZE 8192
#endif

/**
 * Initializes the library's resources, allocating everything needed for making HTTPS requests that requires some warmup
 * (e.g. parsing the x509 CA root certificates into a mbedtls_x509_crt context only needs to be done once). <p>
 * Don't forget to #glitchedhttps_free() again once you're done using glitchedhttps!
 * @return \c 0 on success; mbedtls error code on failure.
 */
GLITCHEDHTTPS_API int glitchedhttps_init();

/**
 * Releases the library's resources.
 * \warning Only call this when you are very sure that there are no more pending requests! <p>
 * GlitchedHTTPS will <strong>NOT</strong> check this for you: make sure to only call this when you're truly done making calls to #glitchedhttps_submit() !
 */
GLITCHEDHTTPS_API void glitchedhttps_free();

/**
 * Submits a given HTTP request and writes the server response into the provided output glitchedhttps_response instance. <p>
 * This allocates memory, so don't forget to {@link #glitchedhttps_response_free()} the output glitchedhttps_response instance after usage!!
 * @param request The glitchedhttps_request instance containing the request parameters and data (e.g. url, body, etc...).
 * @param out The output glitchedhttps_response into which to write the response's data and headers. Must be a pointer to a glitchedhttps_response pointer: will be malloc'ed! Make sure it's fresh!!
 * @return <code>GLITCHEDHTTPS_SUCCESS</code> (zero) if the request was submitted successfully; <code>GLITCHEDHTTPS_{ERROR_ID}</code> if the request couldn't even be submitted (e.g. invalid URL/server not found/no internet/whatever..). Check out the <code>glitchedhttps_exitcodes.h</code> header file to find out more about the glitchedhttps error codes!
 */
GLITCHEDHTTPS_API int glitchedhttps_submit(const struct glitchedhttps_request* request, struct glitchedhttps_response** out);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_H
