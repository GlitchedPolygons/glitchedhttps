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

#include <stdbool.h>
#include <glitchedhttps.h>

#define BUFFER_SIZE 256

int main(int argc, char* argv[])
{
    glitchedhttps_request request = {
        .url = argv[1],
        .method = HTTP_GET,
        .buffer_size = BUFFER_SIZE,
        .ssl_verification_optional = false,
    };

    glitchedhttps_response* response = glitchedhttps_submit(&request);

    const bool success = response != NULL && response->status_code >= 200 && response->status_code < 300;

    if (success)
    {
        printf("\nConnection test SUCCESSFUL!\n");
    }

    printf("\nResponse from %s: \n\n%s\n", request.url, response->content);

    glitchedhttps_response_free(response); // TODO: this segfaults because of the first call to free header also frees the entire remaining array... maybe use a pointerpointer?

    return 0;
}

#undef BUFFER_SIZE
