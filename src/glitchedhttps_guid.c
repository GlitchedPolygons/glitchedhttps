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

#ifdef _WIN32
#include <objbase.h>
#else
#include <uuid/uuid.h>
#endif

#include "glitchedhttps_guid.h"
#include <stdio.h>
#include <string.h>

#define GLITCHEDHTTPS_GUID_LOWERCASE_HYPHENS "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"
#define GLITCHEDHTTPS_GUID_LOWERCASE_NO_HYPHENS "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x"
#define GLITCHEDHTTPS_GUID_UPPERCASE_HYPHENS "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X"
#define GLITCHEDHTTPS_GUID_UPPERCASE_NO_HYPHENS "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X"
#define GLITCHEDHTTPS_GET_GUID_FORMAT(lowercase, hyphens) ((lowercase) ? (hyphens) ? (GLITCHEDHTTPS_GUID_LOWERCASE_HYPHENS) : (GLITCHEDHTTPS_GUID_LOWERCASE_NO_HYPHENS) : (hyphens) ? (GLITCHEDHTTPS_GUID_UPPERCASE_HYPHENS) : (GLITCHEDHTTPS_GUID_UPPERCASE_NO_HYPHENS))

#ifdef _WIN32

struct glitchedhttps_guid glitchedhttps_new_guid(const int lowercase, const int hyphens)
{
    struct glitchedhttps_guid out;
    memset(out.string, '\0', sizeof(out.string));

    GUID guid = { 0 };
    if (CoCreateGuid(&guid) == S_OK)
    {
        snprintf(out.string, sizeof(out.string), GLITCHEDHTTPS_GET_GUID_FORMAT(lowercase, hyphens), guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    }
    return out;
}

#else

struct glitchedhttps_guid glitchedhttps_new_guid(const int lowercase, const int hyphens)
{
    struct glitchedhttps_guid out;
    memset(out.string, '\0', sizeof(out.string));

    uuid_t uuid;
    uuid_generate(uuid);

    char tmp[sizeof(out.string)];
    if (lowercase)
    {
        uuid_unparse_lower(uuid, tmp);
    }
    else
    {
        uuid_unparse_upper(uuid, tmp);
    }

    if (hyphens)
    {
        memcpy(out.string, tmp, sizeof(tmp));
    }
    else
    {
        char* c = out.string;
        for (int i = 0; i < sizeof(tmp); ++i)
        {
            if (tmp[i] != '-')
            {
                *(c++) = tmp[i];
            }
        }
    }

    return out;
}

#endif

#undef GLITCHEDHTTPS_GUID_LOWERCASE_HYPHENS
#undef GLITCHEDHTTPS_GUID_LOWERCASE_NO_HYPHENS
#undef GLITCHEDHTTPS_GUID_UPPERCASE_HYPHENS
#undef GLITCHEDHTTPS_GUID_UPPERCASE_NO_HYPHENS
#undef GLITCHEDHTTPS_GET_GUID_FORMAT

#ifdef __cplusplus
} // extern "C"
#endif
