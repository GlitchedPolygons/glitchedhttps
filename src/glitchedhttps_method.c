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

#include <string.h>
#include "glitchedhttps_debug.h"
#include "glitchedhttps_method.h"

bool glitchedhttps_method_to_string(const enum glitchedhttps_method method, char* out, const size_t out_size)
{
    if (out == NULL)
    {
        _glitchedhttps_log_error("Pointer argument \"out\" is NULL! Please provide a valid output string to write (strncpy) into.", __func__);
        return false;
    }
    if (out_size < 8)
    {
        _glitchedhttps_log_error("Insufficient output buffer size: please allocate at least 8 bytes for the out string!", __func__);
        return false;
    }
    switch (method)
    {
        case GLITCHEDHTTPS_GET:
            strncpy(out, "GET", out_size);
            return true;
        case GLITCHEDHTTPS_HEAD:
            strncpy(out, "HEAD", out_size);
            return true;
        case GLITCHEDHTTPS_POST:
            strncpy(out, "POST", out_size);
            return true;
        case GLITCHEDHTTPS_PATCH:
            strncpy(out, "PATCH", out_size);
            return true;
        case GLITCHEDHTTPS_PUT:
            strncpy(out, "PUT", out_size);
            return true;
        case GLITCHEDHTTPS_DELETE:
            strncpy(out, "DELETE", out_size);
            return true;
        case GLITCHEDHTTPS_CONNECT:
            strncpy(out, "CONNECT", out_size);
            return true;
        case GLITCHEDHTTPS_OPTIONS:
            strncpy(out, "OPTIONS", out_size);
            return true;
        case GLITCHEDHTTPS_TRACE:
            strncpy(out, "TRACE", out_size);
            return true;
        default:
            _glitchedhttps_log_error("Invalid HTTP Method!", __func__);
            return false;
    }
}

#ifdef __cplusplus
} // extern "C"
#endif
