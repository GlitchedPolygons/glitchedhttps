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

#include "glitchedhttps_debug.h"
#include "glitchedhttps_header.h"
#include <stdlib.h>
#include <string.h>

struct glitchedhttps_header* glitchedhttps_header_init(const char* type, const size_t type_length, const char* value, const size_t value_length)
{
    if (type == NULL || value == NULL)
    {
        glitchedhttps_log_error("Header type or value string NULL!", __func__);
        return NULL;
    }

    if (type_length == 0)
    {
        glitchedhttps_log_error("Header type string empty!", __func__);
        return NULL;
    }

    struct glitchedhttps_header* out = malloc(sizeof(struct glitchedhttps_header));
    if (out == NULL)
    {
        glitchedhttps_log_error("OUT OF MEMORY!", __func__);
        return NULL;
    }

    out->type = malloc(sizeof(char) * type_length + 1);
    out->value = malloc(sizeof(char) * value_length + 1);

    if (out->type == NULL || out->value == NULL)
    {
        glitchedhttps_log_error("OUT OF MEMORY!", __func__);
        return NULL;
    }

    memcpy(out->type, type, type_length);
    out->type[type_length] = '\0';

    if (value_length > 0)
    {
        memcpy(out->value, value, value_length);
        out->value[value_length] = '\0';
    }
    else
    {
        out->value[0] = '\0';
    }

    return out;
}

void glitchedhttps_header_free(struct glitchedhttps_header* header)
{
    if (header != NULL)
    {
        free(header->type);
        free(header->value);
        free(header);
    }
}

#ifdef __cplusplus
} // extern "C"
#endif
