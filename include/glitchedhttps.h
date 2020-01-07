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
 *  @author Raphael Beck
 *  @brief Simple, lightweight and straight-forward way of doing HTTP(S) requests with the help of ARM's open-source MbedTLS library.
 *  @see https://github.com/GlitchedPolygons/glitchedhttps
 */

#ifndef GLITCHEDHTTPS_H
#define GLITCHEDHTTPS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <glitchedhttps_exitcodes.h>
#include <glitchedhttps_request.h>
#include <glitchedhttps_response.h>

/**
 * Submits a given HTTP request and writes the server response into the provided output glitchedhttps_response instance. <p>
 * This allocates memory, so don't forget to {@link #glitchedhttps_response_free()} the output glitchedhttps_response instance after usage!!
 * @param request The glitchedhttps_request instance containing the request parameters and data (e.g. url, body, etc...).
 * @param out The output glitchedhttps_response into which to write the response's data and headers. Must be a pointer to a glitchedhttps_response pointer: will be malloc'ed! Make sure it's fresh!!
 * @return <code>GLITCHEDHTTPS_SUCCESS</code> (zero) if the request was submitted successfully; <code>GLITCHEDHTTPS_{ERROR_ID}</code> if the request couldn't even be submitted (e.g. invalid URL/server not found/no internet/whatever..). Check out the <code>glitchedhttps_exitcodes.h</code> header file to find out more about the glitchedhttps error codes!
 */
int glitchedhttps_submit(const struct glitchedhttps_request* request, struct glitchedhttps_response** out);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_H
