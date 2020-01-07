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
#include <glitchedhttps.h>

/* You can set a custom buffer size that will be used for recv() - anything above 8192 will be allocated on the heap! */
static const size_t BUFFER_SIZE = 16384;

int main()
{
    char* url = "https://postman-echo.com/post";
    char* body = "{\"foo\" : \"bar\", \"test\" : \"value\"}";

    struct glitchedhttps_request request = {
            .url = url,
            .method = GLITCHEDHTTPS_POST,
            .buffer_size = BUFFER_SIZE,
            .ssl_verification_optional = false,
            .content_type = "application/json",
            .content_length = strlen(body),
            .content = body
    };

    struct glitchedhttps_response* response = NULL;

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
