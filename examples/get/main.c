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

#include <glitchedhttps.h>

#define BUFFER_SIZE 256

int main()
{
    const char* url = "https://epistle.glitchedpolygons.com/marco";

    glitched_http_request request = {
        .url = (char*)url,
        .method = HTTP_GET,
        .buffer_size = BUFFER_SIZE,
        .ssl_verification_optional = false,
    };

    glitched_http_response* response = glitched_http_submit(&request);

    const bool success = response != NULL && response->status_code == 200 && strcmp(response->content, "polo") == 0;

    glitched_http_response_free(response);

    return 0;
}

#undef BUFFER_SIZE
