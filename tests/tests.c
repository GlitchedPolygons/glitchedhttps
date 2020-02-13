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

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "glitchedhttps.h"
#include "glitchedhttps_debug.h"

static void null_test_success(void** state)
{
    (void)state;
}

bool fail_malloc = false;
bool fail_calloc = false;

void* __real_malloc(size_t size);
void* __real_calloc(size_t size);

void* __wrap_malloc(size_t size)
{
    return fail_malloc ? NULL : __real_malloc(size);
}

void* __wrap_calloc(size_t size)
{
    return fail_calloc ? NULL : __real_calloc(size);
}

static void test_glitchedhttps_method_to_string(void** state)
{
    char out[8];
    assert_false(glitchedhttps_method_to_string(GLITCHEDHTTPS_GET, NULL, 8));
    assert_false(glitchedhttps_method_to_string(GLITCHEDHTTPS_GET, out, 5));
    assert_true(glitchedhttps_method_to_string(GLITCHEDHTTPS_GET, out, 8));
    assert_true(glitchedhttps_method_to_string(GLITCHEDHTTPS_GET, out, sizeof(out)));
    assert_false(glitchedhttps_method_to_string(-1337, out, sizeof(out)));
    for(int i = 0; i <= 8; i++)
    {
        glitchedhttps_method_to_string(i, out, sizeof(out));
        switch(i) 
        {
            case GLITCHEDHTTPS_GET:
                assert_int_equal(strncmp(out, "GET", strlen(out)), 0);
                break;
            case GLITCHEDHTTPS_HEAD:
                assert_int_equal(strncmp(out, "HEAD", strlen(out)), 0);
                break;
            case GLITCHEDHTTPS_POST:
                assert_int_equal(strncmp(out, "POST", strlen(out)), 0);
                break;
            case GLITCHEDHTTPS_PATCH:
                assert_int_equal(strncmp(out, "PATCH", strlen(out)), 0);
                break;
            case GLITCHEDHTTPS_PUT:
                assert_int_equal(strncmp(out, "PUT", strlen(out)), 0);
                break;
            case GLITCHEDHTTPS_DELETE:
                assert_int_equal(strncmp(out, "DELETE", strlen(out)), 0);
                break;
            case GLITCHEDHTTPS_CONNECT:
                assert_int_equal(strncmp(out, "CONNECT", strlen(out)), 0);
                break;
            case GLITCHEDHTTPS_OPTIONS:
                assert_int_equal(strncmp(out, "OPTIONS", strlen(out)), 0);
                break;
            case GLITCHEDHTTPS_TRACE:
                assert_int_equal(strncmp(out, "TRACE", strlen(out)), 0);
                break;
            
        }
    }
}

// --------------------------------------------------------------------------------------------------------------

int main(void)
{
    glitchedhttps_set_error_callback(printf);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_test_success),
        cmocka_unit_test(test_glitchedhttps_method_to_string),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
