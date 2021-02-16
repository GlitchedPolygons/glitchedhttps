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

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <glitchedhttps.h>

int main()
{
    struct glitchedhttps_header additional_headers[] =
    {
            { "Another-Foo", "anotherBar" },
            { "Additional-Headers-Are-Cool", "SGVsbG8gV29ybGQh" },
            { "Yet-Another-Header", "You can add as many of these as you want" }
    };

    struct glitchedhttps_request request;
    glitchedhttps_request_init(&request);

    request.url = "https://postman-echo.com/put";
    request.method = GLITCHEDHTTPS_PUT;
    request.content_type = "application/json";
    request.content = "{\"foo\" : \"bar\", \"test\" : \"value\"}";
    request.content_length = strlen(request.content);
    request.additional_headers = additional_headers;
    request.additional_headers_count = sizeof(additional_headers) / sizeof(struct glitchedhttps_header);

    struct glitchedhttps_response* response = NULL;

    clock_t begin = clock();
    int result = glitchedhttps_submit(&request, &response);
    clock_t end = clock();

    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC * 1000.0;

    const int success =
            result == GLITCHEDHTTPS_SUCCESS
            && response != NULL
            && response->status_code >= 200
            && response->status_code < 300;

    if (success)
    {
        printf("\nConnection test SUCCESSFUL! Status Code: %d\n", response->status_code);
    }

    printf("\nResponse (%d ms) from %s: \n\n%s\n", (int)time_spent, request.url, response != NULL ? response->content : "(NULL)");

    glitchedhttps_response_free(response);

    return 0;
}
