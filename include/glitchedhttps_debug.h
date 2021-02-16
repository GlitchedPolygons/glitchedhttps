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
 *  @file glitchedhttps_debug.h
 *  @brief glitchedhttps debugging/error handling code. Mostly for internal use!
 */

#ifndef GLITCHEDHTTPS_DEBUG_H
#define GLITCHEDHTTPS_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "glitchedhttps_api.h"

/** @private */
GLITCHEDHTTPS_API void glitchedhttps_debug(void* ctx, int level, const char* file, int line, const char* str);

/** @private */
GLITCHEDHTTPS_API void glitchedhttps_log_error(const char* error, const char* origin);

/**
 * Sets the glitchedhttps error callback. <p>
 * If errors occur, they'll be passed as a string into the provided callback function.
 * @param error_callback The function to call when errors occur.
 * @return Whether the callback was set up correctly or not (<code>1</code> for \c true and <code>0</code> for \c false).
 */
GLITCHEDHTTPS_API int glitchedhttps_set_error_callback(void (*error_callback)(const char*));

/**
 * Clears the glitchedhttps error callback (errors won't be printed anymore).
 */
GLITCHEDHTTPS_API int glitchedhttps_unset_error_callback();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_DEBUG_H
