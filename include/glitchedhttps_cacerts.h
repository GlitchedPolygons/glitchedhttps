/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/**
 *  @file glitchedhttps_cacerts.h
 *  @brief Trusted CA certificates chain for SSL connections. <p>
 */

#ifndef GLITCHEDHTTPS_CACERTS_H
#define GLITCHEDHTTPS_CACERTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "glitchedhttps_api.h"
#include "chillbuff.h"
#include "stddef.h"

/**
 * Gets a concatenated string of all trusted CA certificates (NUL-terminated <code>char*</code> string).
 * @return Concatenated string of all trusted CA certificates (NUL-terminated <code>char*</code> string).
 */
GLITCHEDHTTPS_API const char* glitchedhttps_get_ca_certs();

/**
 * Gets the length of the string returned by glitchedhttps_get_ca_certs.
 * @return String length (without the NUL-terminator).
 */
GLITCHEDHTTPS_API size_t glitchedhttps_get_ca_certs_length();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_CACERTS_H
