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

#include "glitchedhttps.h"
#include "glitchedhttps_debug.h"

#include <stddef.h>
#include <string.h>
#include <mbedtls/platform.h>

static void (*glitchedhttps_error_callback)(const char*) = NULL;

void glitchedhttps_debug(void* ctx, int level, const char* file, int line, const char* str)
{
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE*)ctx);
}

void glitchedhttps_log_error(const char* error, const char* origin)
{
    size_t error_msg_length = 64 + strlen(error) + strlen(origin);

    char error_msg_stack[GLITCHEDHTTPS_STACK_BUFFERSIZE];
    memset(error_msg_stack, '\0', sizeof(error_msg_stack));

    char* error_msg_heap = NULL;
    if (error_msg_length > GLITCHEDHTTPS_STACK_BUFFERSIZE)
    {
        error_msg_heap = calloc(error_msg_length, sizeof(char));
        if (error_msg_heap == NULL)
        {
            error_msg_length = sizeof error_msg_stack;
        }
    }

    char* error_msg = error_msg_heap != NULL ? error_msg_heap : error_msg_stack;

    snprintf(error_msg, error_msg_length, "\nGLITCHEDHTTPS ERROR: (%s) %s\n", origin, error);

#ifdef GLITCHEDHTTPS_PRINTF_ERRORS
    printf(error_msg);
#endif

    if (glitchedhttps_error_callback != NULL)
    {
        glitchedhttps_error_callback(error_msg);
    }

    free(error_msg_heap);
}

int glitchedhttps_set_error_callback(void (*error_callback)(const char*))
{
    if (error_callback == NULL)
    {
        glitchedhttps_log_error("The passed error callback is empty; Operation cancelled!", __func__);
        return 0;
    }

    glitchedhttps_error_callback = error_callback;
    return 1;
}

int glitchedhttps_unset_error_callback()
{
    glitchedhttps_error_callback = NULL;
    return 1;
}

#ifdef __cplusplus
} // extern "C"
#endif
