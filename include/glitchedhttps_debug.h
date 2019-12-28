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
 *  @file glitchedhttps_debug.h
 *  @author Raphael Beck
 *  @date 28. December 2019
 *  @brief glitchedhttps debugging/error handling code. Mostly for internal use!
 */

#ifndef GLITCHEDHTTPS_DEBUG_H
#define GLITCHEDHTTPS_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/** @private */
void (*_glitchedhttps_error_callback)(const char*) = NULL;

/** @private */
static void _glitchedhttps_debug(void* ctx, int level, const char* file, int line, const char* str)
{
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE*)ctx);
}

/** @private */
static inline void _glitchedhttps_log_error(const char* error, const char* origin)
{
    char error_msg[64 + strlen(error) + strlen(origin)];
    snprintf(error_msg, sizeof(error_msg), "\nGLITCHEDHTTPS ERROR: (%s) %s\n", origin, error);
    if (_glitchedhttps_error_callback != NULL)
    {
        _glitchedhttps_error_callback(error_msg);
    }
}

/**
 * Sets the glitchedhttps error callback. <p>
 * If errors occur, they'll be passed as a string into the provided callback function.
 * @param error_callback The function to call when errors occur.
 * @return Whether the callback was set up correctly or not (<code>bool</code> as defined in <code>stdbool.h</code>).
 */
static inline bool glitchedhttps_set_error_callback(void (*error_callback)(const char*))
{
    if (error_callback == NULL)
    {
        _glitchedhttps_log_error("The passed error callback is empty; Operation cancelled!", __func__);
        return false;
    }

    _glitchedhttps_error_callback = error_callback;
    return true;
}

/**
 * Clears the glitchedhttps error callback (errors won't be printed anymore).
 */
static inline void glitchedhttps_unset_error_callback()
{
    _glitchedhttps_error_callback = NULL;
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_DEBUG_H
