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

#include <stdio.h>
#include <glitchedhttps.h>

static const size_t BUFFER_SIZE = 1024;

int main()
{
    char* url = "https://postman-echo.com/put";
    char* body = "{\"foo\" : \"bar\", \"test\" : \"value\"}";

    glitchedhttps_header additional_headers[] = {
            { "Another-Foo", "anotherBar" },
            { "Additional-Headers-Are-Cool", "SGVsbG8gV29ybGQh" },
            { "Yet-Another-Header", "You can add as many of these as you want" }
    };

    glitchedhttps_request request = {
            .url = url,
            .method = GLITCHEDHTTPS_PUT,
            .buffer_size = BUFFER_SIZE,
            .ssl_verification_optional = false,
            .content_type = "application/json",
            .content_length = strlen(body),
            .content = body,
            .additional_headers = additional_headers,
            .additional_headers_count = sizeof(additional_headers) / sizeof(glitchedhttps_header)
    };

    glitchedhttps_response* response = NULL;
    int result = glitchedhttps_submit(&request, &response);

    const bool success =
            result == GLITCHEDHTTPS_SUCCESS
            && response != NULL
            && response->status_code >= 200
            && response->status_code < 300;

    if (success)
    {
        printf("\nConnection test SUCCESSFUL! Status Code: %d\n", response->status_code);
    }

    printf("\nResponse from %s: \n\n%s\n", request.url, response != NULL ? response->content : "(NULL)");

    glitchedhttps_response_free(response);

    return 0;
}
