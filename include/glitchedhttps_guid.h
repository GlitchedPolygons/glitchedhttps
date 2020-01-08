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
 *  @file glitchedhttps_guid.h
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
struct glitchedhttps_guid
{
    /** NUL-terminated string containing the GUID. */
    char string[36 + 1];
};

/**
 * Generates a new GUID (a.k.a. UUID).
 * @param lowercase Should the GUID be lowercase or UPPERCASE only?
 * @param hyphens Should the GUID contain hyphen separators?
 * @return The glitchedhttps_guid
 */
struct glitchedhttps_guid glitchedhttps_new_guid(const bool lowercase, const bool hyphens);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_GUID_H
