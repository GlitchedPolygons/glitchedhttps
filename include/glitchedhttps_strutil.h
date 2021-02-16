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
 *  @file glitchedhttps_strutil.h
 *  @brief Useful string-related utility functions.
 */

#ifndef GLITCHEDHTTPS_STRUTIL_H
#define GLITCHEDHTTPS_STRUTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <ctype.h>

/**
 * Compares two strings ignoring UPPER vs. lowercase.
 * @param str1 String to compare.
 * @param str2 String to compare to.
 * @param n How many characters of the string should be compared (starting from index 0)?
 * @return If the strings are equal, <code>0</code> is returned. Otherwise, something else.
 */
int glitchedhttps_strncmpic(const char* str1, const char* str2, size_t n)
{
    size_t cmp = 0;
    int ret = INT_MIN;

    if (str1 == NULL || str2 == NULL)
    {
        return ret;
    }

    while ((*str1 || *str2) && cmp < n)
    {
        if ((ret = tolower((int)(*str1)) - tolower((int)(*str2))) != 0)
        {
            break;
        }
        ++cmp;
        ++str1;
        ++str2;
    }

    return ret;
}

/**
 * Checks whether a given string starts with <code>http://</code>.
 * @param url The URL string to check.
 * @return Whether the passed URL has the http scheme at its beginning or not.
 */
static inline int glitchedhttps_is_http(const char* url)
{
    return strlen(url) >= 7 && strncmp(url, "http://", 7) == 0;
}

/**
 * Checks whether a given string starts with <code>https://</code>.
 * @param url The URL string to check.
 * @return Whether the passed URL has the https scheme at its beginning or not.
 */
static inline int glitchedhttps_is_https(const char* url)
{
    return strlen(url) >= 8 && strncmp(url, "https://", 8) == 0;
}

/**
 * Counts how many digits a number has.
 * @param number The number whose digit count you want to know.
 * @return The total amount of digits found.
 */
static inline size_t glitchedhttps_count_digits(const size_t number)
{
    size_t n = number, digits = 0;
    while (n != 0)
    {
        n /= 10;
        ++digits;
    }
    return digits;
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // GLITCHEDHTTPS_STRUTIL_H
