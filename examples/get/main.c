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
#include <glitchedhttps.h>

int main(int argc, char* argv[])
{
    glitchedhttps_init();

    struct glitchedhttps_request request;
    glitchedhttps_request_init(&request);

    request.url = argv[1];
    request.method = GLITCHEDHTTPS_GET;

    struct glitchedhttps_response* response = NULL;

    clock_t begin = clock();
    const int result = glitchedhttps_submit(&request, &response);
    clock_t end = clock();

    const double time_spent = (double)(end - begin) / CLOCKS_PER_SEC * 1000;

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
    glitchedhttps_free();

    return 0;
}
