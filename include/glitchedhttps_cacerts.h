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

/**
 * Makes GlitchedHTTPS use a custom set of trusted CA certificates. <p>
 * Check out the source file <strong>\c glitchedhttps_cacerts.c</strong> to find out more about how the \p ca_certs parameter should look like (in terms of format). <p>
 * \note If you decide to use this function (and thus provide your own chain of trusted CA certs), call this <strong>BEFORE</strong> the first call to #glitchedhttps_init() !
 * @param ca_certs Concatenated string of all trusted CA certificates to use for HTTPS requests (NUL-terminated <code>char*</code> string). Pass \c NULL to revert back to using the default glitchedhttps chain of CA certificates. If this is not NUL-terminated, welcome to undefined behaviour land :D
 */
GLITCHEDHTTPS_API void glitchedhttps_set_custom_ca_certs(char* ca_certs);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_CACERTS_H
