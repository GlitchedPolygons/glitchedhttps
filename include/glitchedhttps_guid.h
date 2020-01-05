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
 *  @file glitchedhttps_guid.h
 *  @author Raphael Beck
 *  @date 28. December 2019
 *  @brief GUID/UUID generator.
 */

#ifndef GLITCHEDHTTPS_GUID_H
#define GLITCHEDHTTPS_GUID_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#ifdef _WIN32
#include <objbase.h>
#else
#include <uuid/uuid.h>
#endif

/**
 * @brief Struct containing the output from a call to the {@link #glitchedhttps_new_guid()} function. <p>
 * 36 characters (only 32 if you chose to omit the hyphens) + 1 NUL terminator.
 */
typedef struct glitchedhttps_guid
{
    /** NUL-terminated string containing the GUID. */
    char string[36 + 1];
} glitchedhttps_guid;

/**
 * Lowercase, hyphenated GUID string format.
 */
#define GLITCHEDHTTPS_GUID_LOWERCASE_HYPHENS "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"

/**
 * Lowercase GUID without hyphens.
 */
#define GLITCHEDHTTPS_GUID_LOWERCASE_NO_HYPHENS "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x"

/**
 * Uppercase GUID format with dashes.
 */
#define GLITCHEDHTTPS_GUID_UPPERCASE_HYPHENS "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X"

/**
 * Uppercase GUID without dashes.
 */
#define GLITCHEDHTTPS_GUID_UPPERCASE_NO_HYPHENS "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X"

/**
 * Get the correct GUID format string based on two booleans that determine case and hyphenation.
 */
#define GLITCHEDHTTPS_GET_GUID_FORMAT(lowercase, hyphens) ((lowercase) ? (hyphens) ? (GLITCHEDHTTPS_GUID_LOWERCASE_HYPHENS) : (GLITCHEDHTTPS_GUID_LOWERCASE_NO_HYPHENS) : (hyphens) ? (GLITCHEDHTTPS_GUID_UPPERCASE_HYPHENS) : (GLITCHEDHTTPS_GUID_UPPERCASE_NO_HYPHENS))

#ifdef _WIN32

/**
 * Generates a new GUID (a.k.a. UUID).
 * @param lowercase Should the GUID be lowercase or UPPERCASE only?
 * @param hyphens Should the GUID contain hyphen separators?
 * @return The glitchedhttps_guid
 */
glitchedhttps_guid glitchedhttps_new_guid(const bool lowercase, const bool hyphens)
{
    glitchedhttps_guid out;
    memset(out.string, '\0', sizeof(out.string));

    GUID guid = { 0 };
    if (CoCreateGuid(&guid) == S_OK)
    {
        snprintf(out.string, sizeof(out.string), GLITCHEDHTTPS_GET_GUID_FORMAT(lowercase, hyphens), guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    }
    return out;
}

#else

#include <uuid/uuid.h>

/**
 * Generates a new GUID (a.k.a. UUID).
 * @param lowercase Should the GUID be lowercase or UPPERCASE only?
 * @param hyphens Should the GUID contain hyphen separators?
 * @return The glitchedhttps_guid
 */
glitchedhttps_guid glitchedhttps_new_guid(const bool lowercase, const bool hyphens)
{
    glitchedhttps_guid out;
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
        for (int i = 0; i < sizeof(tmp); i++)
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

#endif // GLITCHEDHTTPS_GUID_H
